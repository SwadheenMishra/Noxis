"""Multicast discovery: mDNS/Bonjour, SSDP/UPnP and WS-Discovery (ONVIF).

These are what make device *types* identifiable: phones, TVs, speakers,
printers and cameras announce themselves on these protocols.
"""

from __future__ import annotations

import concurrent.futures
import html
import ipaddress
import re
import socket
import struct
import time
import urllib.parse
import urllib.request
import uuid

# ------------------------------------------------------------ UDP plumbing


def udp_collect(
    packets: list[tuple[bytes, tuple[str, int]]],
    local_ip: str,
    duration: float,
    resend_at: float | None = None,
) -> list[tuple[bytes, str]]:
    """Send packets (unicast or multicast) and collect replies for `duration`."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    replies: list[tuple[bytes, str]] = []
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((local_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(0.2)

        def send_all():
            for data, addr in packets:
                try:
                    s.sendto(data, addr)
                except OSError:
                    pass

        send_all()
        start = time.monotonic()
        resent = resend_at is None
        while (elapsed := time.monotonic() - start) < duration:
            if not resent and elapsed >= resend_at:
                send_all()
                resent = True
            try:
                data, addr = s.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            if addr[0] != local_ip:
                replies.append((data, addr[0]))
    except OSError:
        pass
    finally:
        s.close()
    return replies


# ------------------------------------------------------------- DNS / mDNS

T_A, T_PTR, T_TXT, T_SRV = 1, 12, 16, 33


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(names: list[str], qtype: int = T_PTR, txid: int = 0x5744) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0, len(names), 0, 0, 0)
    return header + b"".join(encode_name(n) + struct.pack("!HH", qtype, 1) for n in names)


def read_name(data: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    end = None
    hops = 0
    while True:
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            hops += 1
            if hops > 40:
                raise ValueError("compression loop")
            continue
        off += 1
        labels.append(data[off:off + length].decode("utf-8", "replace"))
        off += length
    return ".".join(labels), (end if end is not None else off)


def parse_dns(data: bytes) -> list[dict]:
    """Parse every resource record in a DNS message (answers + additionals)."""
    records: list[dict] = []
    try:
        _, _, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
        off = 12
        for _ in range(qd):
            _, off = read_name(data, off)
            off += 4
        for _ in range(an + ns + ar):
            name, off = read_name(data, off)
            rtype, _, _, rdlen = struct.unpack_from("!HHIH", data, off)
            off += 10
            rd = off
            off += rdlen
            rec: dict = {"name": name, "type": rtype}
            if rtype == T_PTR:
                rec["target"] = read_name(data, rd)[0]
            elif rtype == T_SRV:
                _, _, port = struct.unpack_from("!HHH", data, rd)
                rec["port"] = port
                rec["target"] = read_name(data, rd + 6)[0]
            elif rtype == T_TXT:
                txt, i = [], rd
                while i < rd + rdlen:
                    ln = data[i]
                    txt.append(data[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                    i += 1 + ln
                rec["txt"] = txt
            elif rtype == T_A and rdlen == 4:
                rec["address"] = socket.inet_ntoa(data[rd:rd + 4])
            records.append(rec)
    except (IndexError, struct.error, ValueError):
        pass
    return records


MDNS_SERVICES = [
    "_services._dns-sd._udp.local",
    "_airplay._tcp.local", "_raop._tcp.local", "_companion-link._tcp.local",
    "_apple-mobdev2._tcp.local", "_rdlink._tcp.local", "_device-info._tcp.local",
    "_googlecast._tcp.local", "_spotify-connect._tcp.local", "_sonos._tcp.local",
    "_amzn-wplay._tcp.local", "_hap._tcp.local", "_homekit._tcp.local",
    "_matter._tcp.local", "_matterc._udp.local", "_esphomelib._tcp.local",
    "_arduino._tcp.local", "_wled._tcp.local", "_shelly._tcp.local",
    "_http._tcp.local", "_https._tcp.local", "_rtsp._tcp.local",
    "_printer._tcp.local", "_ipp._tcp.local", "_ipps._tcp.local",
    "_pdl-datastream._tcp.local", "_scanner._tcp.local", "_smb._tcp.local",
    "_afpovertcp._tcp.local", "_workstation._tcp.local", "_ssh._tcp.local",
    "_sftp-ssh._tcp.local", "_octoprint._tcp.local", "_mqtt._tcp.local",
    "_home-assistant._tcp.local", "_androidtvremote2._tcp.local",
    "_nvstream._tcp.local", "_xbox._tcp.local", "_miio._udp.local",
]
_TXT_KEYS = {"model", "md", "fn", "board", "platform", "friendly_name", "ty",
             "product", "am", "manufacturer", "version", "mac", "n", "name"}


def _service_type(name: str) -> str | None:
    m = re.search(r"(_[\w-]+\._(?:tcp|udp))\.local$", name)
    return m.group(1) if m else None


def mdns_discover(local_ip: str, duration: float = 3.0) -> dict[str, dict]:
    """Return {ip: {"services": set, "instances": set, "hostnames": set, "txt": {}}}."""
    dest = ("224.0.0.251", 5353)
    packets = [
        (build_query(MDNS_SERVICES[i:i + 10], txid=0x5744 + i), dest)
        for i in range(0, len(MDNS_SERVICES), 10)
    ]
    replies = udp_collect(packets, local_ip, duration, resend_at=1.0)

    # Second round: service types we learned from _services enumeration.
    discovered: set[str] = set()
    for data, _ in replies:
        for rec in parse_dns(data):
            if rec["type"] == T_PTR and rec["name"] == "_services._dns-sd._udp.local":
                discovered.add(rec["target"])
    extra = sorted(discovered - set(MDNS_SERVICES))[:30]
    if extra:
        packets = [(build_query(extra[i:i + 10]), dest) for i in range(0, len(extra), 10)]
        replies += udp_collect(packets, local_ip, 1.5)

    result: dict[str, dict] = {}
    for data, src in replies:
        entry = result.setdefault(
            src, {"services": set(), "instances": set(), "hostnames": set(), "txt": {}}
        )
        for rec in parse_dns(data):
            if rec["type"] == T_PTR:
                if rec["name"] == "_services._dns-sd._udp.local":
                    st = _service_type(rec["target"])
                    if st:
                        entry["services"].add(st)
                else:
                    st = _service_type(rec["name"])
                    if st:
                        entry["services"].add(st)
                        inst = rec["target"]
                        suffix = "." + rec["name"]
                        if inst.endswith(suffix):
                            inst = inst[: -len(suffix)]
                        entry["instances"].add(inst)
            elif rec["type"] == T_SRV:
                entry["hostnames"].add(rec["target"])
            elif rec["type"] == T_A and rec["address"] == src:
                entry["hostnames"].add(rec["name"])
            elif rec["type"] == T_TXT:
                for item in rec["txt"]:
                    k, _, v = item.partition("=")
                    if k.lower() in _TXT_KEYS and v and k.lower() not in entry["txt"]:
                        entry["txt"][k.lower()] = v[:80]
    return {ip: e for ip, e in result.items() if any(e.values())}


# ----------------------------------------------------------------- SSDP

_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: {st}\r\n"
    "USER-AGENT: Noxis/0.1 UPnP/1.1\r\n\r\n"
)


def _parse_headers(text: str) -> dict[str, str]:
    headers = {}
    for line in text.split("\r\n")[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    return headers


def ssdp_discover(local_ip: str, duration: float = 3.0) -> dict[str, dict]:
    dest = ("239.255.255.250", 1900)
    packets = [(_MSEARCH.format(st=st).encode(), dest) for st in ("ssdp:all", "upnp:rootdevice")]
    result: dict[str, dict] = {}
    for data, src in udp_collect(packets, local_ip, duration, resend_at=1.0):
        h = _parse_headers(data.decode("utf-8", "replace"))
        entry = result.setdefault(src, {"servers": set(), "locations": set(), "types": set()})
        if h.get("server"):
            entry["servers"].add(h["server"][:120])
        if h.get("location"):
            entry["locations"].add(h["location"])
        if h.get("st"):
            entry["types"].add(h["st"][:120])
    return result


_UPNP_TAGS = ("friendlyName", "manufacturer", "modelName", "modelNumber",
              "modelDescription", "deviceType")


def _fetch_description(url: str) -> dict[str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Noxis/0.1"})
    with urllib.request.urlopen(req, timeout=2.5) as resp:  # noqa: S310 (LAN only)
        body = resp.read(200_000).decode("utf-8", "replace")
    info = {}
    for tag in _UPNP_TAGS:
        m = re.search(rf"<(?:\w+:)?{tag}>\s*(.*?)\s*</(?:\w+:)?{tag}>", body, re.S)
        if m and m.group(1):
            info[tag] = html.unescape(m.group(1))[:120]
    return info


def fetch_upnp_descriptions(ssdp: dict[str, dict], network: ipaddress.IPv4Network) -> dict[str, dict]:
    """GET each device's UPnP description XML (only for hosts inside our LAN)."""
    jobs: list[tuple[str, str]] = []
    for ip, entry in ssdp.items():
        for loc in sorted(entry["locations"])[:2]:
            host = urllib.parse.urlparse(loc).hostname
            try:
                if host and ipaddress.ip_address(host) in network:
                    jobs.append((ip, loc))
            except ValueError:
                continue
    out: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_fetch_description, loc): ip for ip, loc in jobs}
        for fut in concurrent.futures.as_completed(futures):
            try:
                info = fut.result()
            except Exception:  # noqa: BLE001 - any HTTP/XML failure is just "no info"
                continue
            ip = futures[fut]
            merged = out.setdefault(ip, {})
            for k, v in info.items():
                merged.setdefault(k, v)
    return out


# --------------------------------------------------- WS-Discovery / ONVIF

_WSD_PROBE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    "<e:Header><w:MessageID>uuid:{msgid}</w:MessageID>"
    '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
    '<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
    "</e:Header><e:Body><d:Probe>{types}</d:Probe></e:Body></e:Envelope>"
)


def _tag(body: str, name: str) -> str:
    m = re.search(rf"<(?:\w+:)?{name}[^>]*>(.*?)</(?:\w+:)?{name}>", body, re.S)
    return html.unescape(m.group(1)).strip() if m else ""


def parse_wsd(body: str) -> dict:
    types = _tag(body, "Types")
    scopes = _tag(body, "Scopes")
    info: dict = {"types": types.split(), "xaddrs": _tag(body, "XAddrs")[:200]}
    is_onvif = "NetworkVideoTransmitter" in types or "onvif://www.onvif.org" in scopes
    if is_onvif:
        onvif: dict[str, str] = {}
        for scope in scopes.split():
            m = re.match(r"onvif://www\.onvif\.org/(name|hardware|location|type)/(.+)", scope)
            if m:
                key, value = m.group(1), urllib.parse.unquote(m.group(2))
                onvif[key] = (onvif[key] + ", " + value) if key in onvif else value
        info["onvif"] = onvif or {"name": "ONVIF device"}
    return info


def wsd_discover(local_ip: str, duration: float = 3.0) -> dict[str, dict]:
    dest = ("239.255.255.250", 3702)
    packets = [
        (_WSD_PROBE.format(msgid=uuid.uuid4(), types="<d:Types>dn:NetworkVideoTransmitter</d:Types>").encode(), dest),
        (_WSD_PROBE.format(msgid=uuid.uuid4(), types="").encode(), dest),
    ]
    result: dict[str, dict] = {}
    for data, src in udp_collect(packets, local_ip, duration, resend_at=1.2):
        info = parse_wsd(data.decode("utf-8", "replace"))
        entry = result.setdefault(src, {"types": set(), "onvif": None})
        entry["types"].update(info["types"])
        if info.get("onvif"):
            entry["onvif"] = info["onvif"]
    return result
