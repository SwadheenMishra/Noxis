"""Nearby Wi-Fi networks: camera hotspots and evil twins.

This sees networks you're *not* connected to, so it still works when the Wi-Fi
you're on hides other devices, and it catches cameras that broadcast their
own hotspot instead of joining the main network.
"""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field

from .models import Finding
from .util import IS_WINDOWS, is_randomized_mac, normalize_mac, run


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    signal: int | None = None  # percent
    channel: str | None = None
    band: str | None = None
    auth: str | None = None
    encryption: str | None = None
    radio: str | None = None
    vendor: str | None = None
    seen_rounds: list[int] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return (self.auth or "").lower() in ("open", "none", "")

    def to_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------ scanning


def _trigger_windows_scan() -> bool:
    """Ask every Wi-Fi adapter for a fresh scan (netsh only shows the cache)."""
    import ctypes
    from ctypes import POINTER, Structure, byref, c_ubyte, c_uint, c_ulong, c_ushort, c_void_p, c_wchar

    class GUID(Structure):
        _fields_ = [("Data1", c_ulong), ("Data2", c_ushort), ("Data3", c_ushort), ("Data4", c_ubyte * 8)]

    class InterfaceInfo(Structure):
        _fields_ = [("guid", GUID), ("description", c_wchar * 256), ("state", c_uint)]

    class InterfaceList(Structure):
        _fields_ = [("count", c_ulong), ("index", c_ulong), ("items", InterfaceInfo * 1)]

    try:
        api = ctypes.WinDLL("wlanapi")
    except OSError:
        return False
    api.WlanOpenHandle.argtypes = [c_ulong, c_void_p, POINTER(c_ulong), POINTER(c_void_p)]
    api.WlanEnumInterfaces.argtypes = [c_void_p, c_void_p, POINTER(POINTER(InterfaceList))]
    api.WlanScan.argtypes = [c_void_p, POINTER(GUID), c_void_p, c_void_p, c_void_p]
    api.WlanFreeMemory.argtypes = [c_void_p]
    api.WlanCloseHandle.argtypes = [c_void_p, c_void_p]

    handle, version = c_void_p(), c_ulong()
    if api.WlanOpenHandle(2, None, byref(version), byref(handle)) != 0:
        return False
    try:
        plist = POINTER(InterfaceList)()
        if api.WlanEnumInterfaces(handle, None, byref(plist)) != 0:
            return False
        items = ctypes.cast(ctypes.addressof(plist.contents.items), POINTER(InterfaceInfo))
        ok = False
        for i in range(plist.contents.count):
            ok |= api.WlanScan(handle, byref(items[i].guid), None, None, None) == 0
        api.WlanFreeMemory(plist)
        return ok
    finally:
        api.WlanCloseHandle(handle, None)


def parse_netsh_networks(text: str) -> list[AccessPoint]:
    aps: list[AccessPoint] = []
    ssid = auth = enc = None
    ap: AccessPoint | None = None
    for line in text.splitlines():
        if m := re.match(r"^SSID \d+\s*:\s?(.*)$", line):
            ssid, auth, enc, ap = m.group(1).strip(), None, None, None
            continue
        if ssid is None:
            continue
        if m := re.match(r"^\s+Authentication\s*:\s*(.+)$", line):
            auth = m.group(1).strip()
        elif m := re.match(r"^\s+Encryption\s*:\s*(.+)$", line):
            enc = m.group(1).strip()
        elif m := re.match(r"^\s+BSSID \d+\s*:\s*(\S+)", line):
            mac = normalize_mac(m.group(1))
            if mac:
                ap = AccessPoint(ssid=ssid, bssid=mac, auth=auth, encryption=enc)
                aps.append(ap)
        elif ap is not None:
            if m := re.match(r"^\s+Signal\s*:\s*(\d+)%", line):
                ap.signal = int(m.group(1))
            elif m := re.match(r"^\s+Channel\s*:\s*(\S+)", line):
                ap.channel = m.group(1)
            elif m := re.match(r"^\s+Band\s*:\s*(.+)$", line):
                ap.band = m.group(1).strip()
            elif m := re.match(r"^\s+Radio type\s*:\s*(.+)$", line):
                ap.radio = m.group(1).strip()
    return aps


def parse_nmcli(text: str) -> list[AccessPoint]:
    aps = []
    for line in text.splitlines():
        parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
        if len(parts) < 5:
            continue
        ssid, bssid, signal, chan, security = parts[:5]
        mac = normalize_mac(bssid)
        if mac:
            aps.append(AccessPoint(ssid=ssid, bssid=mac, signal=int(signal or 0), channel=chan,
                                   auth=security or "Open"))
    return aps


WIFI_SCAN_ACTION = "org.freedesktop.NetworkManager.wifi.scan"

STALE_NOTE = ("NetworkManager doesn't let this user ask for a fresh Wi-Fi scan, so this list "
              "may be old and miss nearby networks. `noxis service install` allows it for "
              "your account (that permission only), or run the scan with sudo.")


def parse_nm_permissions(text: str) -> dict[str, str]:
    """`nmcli -t -f PERMISSION,VALUE general permissions` -> {permission: yes|no|auth}."""
    perms = {}
    for line in text.splitlines():
        name, _, value = line.strip().rpartition(":")
        if name:
            perms[name] = value.strip().lower()
    return perms


def rescan_allowed() -> bool:
    """Can we make NetworkManager scan right now? (Linux.) Without it, nmcli
    quietly returns its old list: often just the network we're connected to."""
    if IS_WINDOWS:
        return True
    import os
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    out = run(["nmcli", "-t", "-f", "PERMISSION,VALUE", "general", "permissions"])
    if not out:
        return True  # no NetworkManager to ask: nothing to warn about
    return parse_nm_permissions(out).get(WIFI_SCAN_ACTION, "yes") == "yes"


def power_save_hint() -> str | None:
    """Linux: a hint if Wi-Fi power saving is on. The chip then naps between
    beacons and loses some broadcasts (on a Pi, about a fifth of an ARP sweep),
    which hurts device discovery and network-sweep detection."""
    if IS_WINDOWS:
        return None
    ifaces = re.findall(r"^\s*Interface\s+(\S+)", run(["iw", "dev"]), re.M)
    on = [i for i in ifaces
          if re.search(r"Power save:\s*on", run(["iw", "dev", i, "get", "power_save"]), re.I)]
    if not on:
        return None
    iface = on[0]
    conn = None
    for line in run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"]).splitlines():
        name, _, dev = line.rpartition(":")
        if dev == iface and name:
            conn = name.replace("\\:", ":")
    keep = (f" To keep it off: sudo nmcli connection modify \"{conn}\" 802-11-wireless.powersave 2"
            if conn else "")
    return (f"Wi-Fi power saving is on ({iface}), so it misses some packets: devices and network "
            f"sweeps can slip past. Turn it off until reboot: sudo iw dev {iface} set power_save "
            f"off.{keep}")


def scan_nearby(oui=None, trigger: bool = True) -> list[AccessPoint]:
    if IS_WINDOWS:
        if trigger and _trigger_windows_scan():
            time.sleep(4)  # scans take 2-4s; netsh then shows fresh results
        aps = parse_netsh_networks(run(["netsh", "wlan", "show", "networks", "mode=bssid"]))
    else:
        aps = parse_nmcli(run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY",
                               "dev", "wifi", "list", "--rescan", "yes" if trigger else "no"], timeout=30))
    if oui is not None:
        for ap in aps:
            ap.vendor = oui.lookup(ap.bssid)
    return aps


def connected_bssid() -> str | None:
    if IS_WINDOWS:
        m = re.search(r"^\s*(?:AP )?BSSID\s*:\s*(\S+)", run(["netsh", "wlan", "show", "interfaces"]), re.M)
        return normalize_mac(m.group(1)) if m else None
    out = run(["nmcli", "-t", "-f", "ACTIVE,BSSID", "dev", "wifi"])
    for line in out.splitlines():
        if line.startswith("yes:"):
            return normalize_mac(line[4:].replace("\\:", ":"))
    return None


# ----------------------------------------------------------- assessment

# Default hotspot names of cheap Wi-Fi / "spy" cameras.
CAMERA_SSID_STRONG = re.compile(
    r"^(ipc|ipcam|ip-cam|ipcamera|hdcam|hd-cam|hdwificam|smart_?cam|wifi_?cam|wificam|mini_?cam|"
    r"spy_?cam|cloud_?cam|v380|yoosee|lookcam|icsee|camhi|ezviz|wyze|reolink|tapo_?cam|imou|"
    r"dvr|nvr|camera)", re.I)
CAMERA_SSID_WEAK = re.compile(r"^(mv\d|jxl|p2p[-_]|gw_ap|cam[-_]\w+|xm_|a9[-_ ]|x5[-_ ])", re.I)
ESP_SSID = re.compile(r"^(esp[-_]|esp32|esp8266|ai-thinker|nodemcu|tasmota|wled)", re.I)
CAMERA_VENDOR = re.compile(r"hikvision|dahua|amcrest|reolink|baichuan|wyze|foscam|ezviz|vivotek|"
                           r"axis comm|hanwha|uniview|lorex|swann|arlo|imou|xiongmai", re.I)


def _same_hardware(a: str, b: str) -> bool:
    """Routers give each band/SSID a slightly different BSSID: usually the
    same middle bytes with the first or last byte changed."""
    pa, pb = a.split(":"), b.split(":")
    return pa[1:5] == pb[1:5] or pa[:5] == pb[:5]


def assess_nearby(aps: list[AccessPoint], ssid: str | None, my_bssid: str | None,
                  known_bssids: list[str]) -> list[Finding]:
    """Per-AP findings are attached to the AP; returns network-level findings."""
    net_findings: list[Finding] = []
    mine = next((ap for ap in aps if ap.bssid == my_bssid), None)

    for ap in aps:
        ap.findings = []
        name = ap.ssid or ""
        vendor = ap.vendor or ""
        if CAMERA_SSID_STRONG.match(name) or CAMERA_VENDOR.search(vendor):
            ap.findings.append(Finding(
                "high", "Camera-style Wi-Fi hotspot nearby",
                f"'{name or '(hidden)'}'" + (f" from {vendor}" if vendor else "")
                + " looks like a Wi-Fi camera broadcasting its own hotspot. These cameras don't "
                "need the building's Wi-Fi, so a network scan alone won't find them. A strong "
                "signal means it's close: walk around and watch the signal rise."))
        elif CAMERA_SSID_WEAK.match(name):
            ap.findings.append(Finding(
                "medium", "Possible camera hotspot nearby",
                f"'{name}' matches name patterns used by some cheap cameras."))
        elif ESP_SSID.match(name) or re.search(r"espressif", vendor, re.I):
            ap.findings.append(Finding(
                "medium", "Microcontroller hotspot nearby",
                f"'{name or '(hidden)'}' is broadcast by an ESP32/ESP8266-style board. Common for "
                "smart plugs in setup mode, but also for DIY gadgets, including ESP32-CAMs."))
        if not name and (ap.signal or 0) >= 70:
            ap.findings.append(Finding(
                "low", "Strong hidden network nearby",
                "A network with no name is broadcasting close to you. Often mesh-router "
                "backhaul, but hidden networks are also used by covert devices."))

        # Evil twin: same name as the network we're on, but different hardware.
        if ssid and name == ssid and ap.bssid != my_bssid:
            if ap.bssid in known_bssids:
                continue
            related = my_bssid and _same_hardware(ap.bssid, my_bssid)
            if mine and ap.is_open and not mine.is_open:
                ap.findings.append(Finding(
                    "high", "Open copy of your network's name",
                    f"An unencrypted network is also called '{ssid}'. This is a classic evil-twin "
                    "trick to make devices connect to an attacker's hotspot. Don't connect to it."))
            elif known_bssids:
                ap.findings.append(Finding(
                    "medium", "New access point using your network's name",
                    f"{ap.bssid} broadcasts '{ssid}' but wasn't there when you trusted this "
                    "network. Fine if you added a mesh node or extender; otherwise it may be an "
                    "evil twin."))
            elif not related and not is_randomized_mac(ap.bssid):
                ap.findings.append(Finding(
                    "medium", "Different hardware using your network's name",
                    f"{ap.bssid}" + (f" ({ap.vendor})" if ap.vendor else "")
                    + f" also broadcasts '{ssid}' but doesn't look like the router you're "
                    "connected to. Fine for mesh systems or extenders; otherwise it may be an evil twin."))

    rotating = (my_bssid and known_bssids and is_randomized_mac(my_bssid)
                and all(is_randomized_mac(b) for b in known_bssids))
    if my_bssid and known_bssids and my_bssid not in known_bssids and rotating:
        # Phone hotspots (iPhone, Android) pick a new random BSSID now and then.
        net_findings.append(Finding(
            "info", "This hotspot changes its hardware address",
            f"'{ssid}' now uses {my_bssid}. Phone hotspots randomize this address, so a change "
            "is normal and Noxis can't use it to spot an evil twin here."))
    elif my_bssid and known_bssids and my_bssid not in known_bssids:
        net_findings.append(Finding(
            "high", "Connected to an access point you haven't trusted",
            f"You're connected to '{ssid}' through {my_bssid}, which wasn't one of the access "
            "points you trusted for this network. If you didn't add new Wi-Fi hardware, you may "
            "be on an evil twin."))
    return net_findings
