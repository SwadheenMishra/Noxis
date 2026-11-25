"""Work out which network we're on: our IP, subnet, gateway, MAC, SSID."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from pathlib import Path

from .models import NetworkInfo
from .util import IS_MAC, IS_WINDOWS, normalize_mac, run


def _local_ip() -> str:
    # UDP "connect" picks the outbound interface without sending anything.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


IF_TYPE_WIFI = 71  # IF_TYPE_IEEE80211


def _adapters_windows() -> list[dict]:
    """Every adapter's IPv4 settings from GetAdaptersAddresses (iphlpapi):
    one fast system call instead of starting PowerShell (which took 6-12 s)."""
    import ctypes
    from ctypes import POINTER, Structure, Union, byref, c_char_p, c_int, c_ubyte, c_ulong, c_ulonglong, \
        c_ushort, c_void_p, c_wchar_p

    class SOCKET_ADDRESS(Structure):
        _fields_ = [("lpSockaddr", c_void_p), ("iSockaddrLength", c_int)]

    class _Head(Structure):
        _fields_ = [("Length", c_ulong), ("Flags", c_ulong)]

    class _HeadU(Union):
        _fields_ = [("Alignment", c_ulonglong), ("s", _Head)]

    class UNICAST(Structure):
        pass
    UNICAST._fields_ = [("u", _HeadU), ("Next", POINTER(UNICAST)), ("Address", SOCKET_ADDRESS),
                        ("PrefixOrigin", c_int), ("SuffixOrigin", c_int), ("DadState", c_int),
                        ("ValidLifetime", c_ulong), ("PreferredLifetime", c_ulong),
                        ("LeaseLifetime", c_ulong), ("OnLinkPrefixLength", c_ubyte)]

    class ADDRESS(Structure):  # DNS server and gateway entries share this shape
        pass
    ADDRESS._fields_ = [("u", _HeadU), ("Next", POINTER(ADDRESS)), ("Address", SOCKET_ADDRESS)]

    class ADAPTER(Structure):
        pass
    ADAPTER._fields_ = [
        ("u", _HeadU), ("Next", POINTER(ADAPTER)), ("AdapterName", c_char_p),
        ("FirstUnicastAddress", POINTER(UNICAST)), ("FirstAnycastAddress", c_void_p),
        ("FirstMulticastAddress", c_void_p), ("FirstDnsServerAddress", POINTER(ADDRESS)),
        ("DnsSuffix", c_wchar_p), ("Description", c_wchar_p), ("FriendlyName", c_wchar_p),
        ("PhysicalAddress", c_ubyte * 8), ("PhysicalAddressLength", c_ulong), ("Flags", c_ulong),
        ("Mtu", c_ulong), ("IfType", c_ulong), ("OperStatus", c_int), ("Ipv6IfIndex", c_ulong),
        ("ZoneIndices", c_ulong * 16), ("FirstPrefix", c_void_p),
        ("TransmitLinkSpeed", c_ulonglong), ("ReceiveLinkSpeed", c_ulonglong),
        ("FirstWinsServerAddress", c_void_p), ("FirstGatewayAddress", POINTER(ADDRESS)),
    ]

    def ipv4(sa: SOCKET_ADDRESS) -> str | None:
        if not sa.lpSockaddr or sa.iSockaddrLength < 8:
            return None
        family = ctypes.cast(sa.lpSockaddr, POINTER(c_ushort))[0]
        if family != socket.AF_INET:
            return None
        raw = ctypes.string_at(sa.lpSockaddr + 4, 4)  # sockaddr_in: family, port, address
        return socket.inet_ntoa(raw)

    def walk(first):
        node = first
        while node:
            yield node.contents
            node = node.contents.Next

    api = ctypes.WinDLL("iphlpapi")
    api.GetAdaptersAddresses.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong)]
    flags = 0x0002 | 0x0004 | 0x0080  # skip anycast, skip multicast, include gateways
    size = c_ulong(32_768)
    for _ in range(3):  # the list can grow between the size query and the call
        buf = ctypes.create_string_buffer(size.value)
        rc = api.GetAdaptersAddresses(socket.AF_INET, flags, None, buf, byref(size))
        if rc != 111:  # ERROR_BUFFER_OVERFLOW: retry with the size Windows asked for
            break
    if rc != 0:
        raise OSError(f"GetAdaptersAddresses failed ({rc})")

    adapters = []
    for a in walk(ctypes.cast(buf, POINTER(ADAPTER))):
        mac_len = min(a.PhysicalAddressLength, 8)
        adapters.append({
            "iface": a.FriendlyName,
            "if_type": a.IfType,
            "up": a.OperStatus == 1,
            "mac": "-".join(f"{b:02X}" for b in a.PhysicalAddress[:mac_len]) if mac_len == 6 else None,
            "addresses": [(ip, u.OnLinkPrefixLength) for u in walk(a.FirstUnicastAddress)
                          if (ip := ipv4(u.Address))],
            "gateways": [ip for g in walk(a.FirstGatewayAddress) if (ip := ipv4(g.Address))],
            "dns": [ip for d in walk(a.FirstDnsServerAddress) if (ip := ipv4(d.Address))],
        })
    return adapters


def _windows_ssid(info: dict) -> str | None:
    # netsh is exact, but newer Windows hides the SSID without location access.
    wlan = run(["netsh", "wlan", "show", "interfaces"], timeout=10)
    m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", wlan, re.M)
    if m:
        return m.group(1)
    if info.get("if_type") == IF_TYPE_WIFI or info.get("iface", "").lower().startswith(("wi-fi", "wlan")):
        # Fall back to the connection profile name (one cmdlet, under a second).
        # Profile names get " 2", " 3" suffixes for repeats; strip them.
        name = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    f"(Get-NetConnectionProfile -InterfaceAlias '{info['iface']}' "
                    "-ErrorAction SilentlyContinue | Select-Object -First 1).Name"], timeout=15).strip()
        if name:
            return re.sub(r"\s+\d+$", "", name)
    return None


def _windows_fast(ip: str) -> dict:
    adapter = next(a for a in _adapters_windows() if any(addr == ip for addr, _ in a["addresses"]))
    info = {
        "prefix": next(p for addr, p in adapter["addresses"] if addr == ip),
        "gateway": adapter["gateways"][0] if adapter["gateways"] else None,
        "mac": adapter["mac"],
        "iface": adapter["iface"],
        "if_type": adapter["if_type"],
        "dns": adapter["dns"],
    }
    ssid = _windows_ssid(info)
    if ssid:
        info["ssid"] = ssid
    return info


def _windows(ip: str) -> dict:
    try:
        return _windows_fast(ip)
    except (OSError, StopIteration, ValueError, AttributeError):
        return _windows_powershell(ip)  # slow but proven; only if the API call fails


def _windows_powershell(ip: str) -> dict:
    ps = (
        f"$a = Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{ip}' -ErrorAction Stop | Select-Object -First 1; "
        "$c = Get-NetIPConfiguration -InterfaceIndex $a.InterfaceIndex; "
        "$n = Get-NetAdapter -InterfaceIndex $a.InterfaceIndex; "
        "$p = Get-NetConnectionProfile -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "$d = @((Get-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses); "
        "[pscustomobject]@{prefix=$a.PrefixLength; "
        "gateway=(@($c.IPv4DefaultGateway) | Select-Object -First 1).NextHop; "
        "mac=$n.MacAddress; iface=$n.Name; profile=$p.Name; dns=$d} | ConvertTo-Json -Compress"
    )
    out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=25)
    info: dict = {}
    try:
        data = json.loads(out.strip() or "{}")
        info = {
            "prefix": data.get("prefix"),
            "gateway": data.get("gateway"),
            "mac": data.get("mac"),
            "iface": data.get("iface"),
            "dns": [x for x in (data.get("dns") or []) if x],
        }
        profile = data.get("profile")
    except (json.JSONDecodeError, AttributeError):
        profile = None

    # SSID: netsh is exact, but newer Windows hides it without location access.
    wlan = run(["netsh", "wlan", "show", "interfaces"], timeout=10)
    m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", wlan, re.M)
    if m:
        info["ssid"] = m.group(1)
    elif profile and info.get("iface", "").lower().startswith(("wi-fi", "wlan", "wireless")):
        # Profile names get " 2", " 3" suffixes for repeats; strip them.
        info["ssid"] = re.sub(r"\s+\d+$", "", profile)
    return info


def _linux(ip: str) -> dict:
    info: dict = {}
    try:
        for iface in json.loads(run(["ip", "-j", "-4", "addr", "show"]) or "[]"):
            for addr in iface.get("addr_info", []):
                if addr.get("local") == ip:
                    info["prefix"] = addr.get("prefixlen")
                    info["iface"] = iface.get("ifname")
                    info["mac"] = iface.get("address")
        routes = json.loads(run(["ip", "-j", "route", "show", "default"]) or "[]")
        if routes:
            info["gateway"] = routes[0].get("gateway")
    except json.JSONDecodeError:
        pass
    if info.get("iface") and not info.get("mac"):
        p = Path(f"/sys/class/net/{info['iface']}/address")
        if p.exists():
            info["mac"] = p.read_text().strip()
    ssid = run(["iwgetid", "-r"], timeout=5).strip()
    if ssid:
        info["ssid"] = ssid
    info["dns"] = _unix_dns()
    return info


def _unix_dns() -> list[str]:
    try:
        text = Path("/etc/resolv.conf").read_text()
    except OSError:
        return []
    servers = re.findall(r"^\s*nameserver\s+(\d+\.\d+\.\d+\.\d+)", text, re.M)
    if servers and all(s.startswith("127.") for s in servers):
        # systemd-resolved stub: ask it for the real upstream servers.
        real = re.findall(r"(\d+\.\d+\.\d+\.\d+)", run(["resolvectl", "dns"], timeout=5))
        servers = real or servers
    return list(dict.fromkeys(servers))


def _macos(ip: str) -> dict:
    info: dict = {}
    m = re.search(r"gateway:\s*(\S+)", run(["route", "-n", "get", "default"]))
    if m:
        info["gateway"] = m.group(1)
    m = re.search(r"interface:\s*(\S+)", run(["route", "-n", "get", "default"]))
    if m:
        info["iface"] = m.group(1)
        out = run(["ifconfig", m.group(1)])
        mm = re.search(r"ether\s+(\S+)", out)
        if mm:
            info["mac"] = mm.group(1)
        mm = re.search(r"netmask\s+0x([0-9a-f]{8})", out)
        if mm:
            info["prefix"] = bin(int(mm.group(1), 16)).count("1")
    info["dns"] = _unix_dns()
    return info


def get_network_info() -> NetworkInfo:
    ip = _local_ip()
    if IS_WINDOWS:
        info = _windows(ip)
    elif IS_MAC:
        info = _macos(ip)
    else:
        info = _linux(ip)
    prefix = int(info.get("prefix") or 24)
    cidr = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    return NetworkInfo(
        local_ip=ip,
        prefix=prefix,
        cidr=cidr,
        gateway_ip=info.get("gateway") or None,
        local_mac=normalize_mac(info.get("mac")),
        interface=info.get("iface"),
        ssid=info.get("ssid"),
        dns=info.get("dns") or [],
    )
