"""Router port forwards opened through UPnP.

UPnP lets any program on any device ask the router to forward a port from
the internet to itself, without a password and without telling you. Games
and video calls use it, and so does malware: an infected camera can open
its own door to the internet this way. This reads the router's list of
those forwards. It only reads: Noxis never adds or removes a forward.

Forwards you typed into the router's admin page usually aren't in this list
(that needs the router password), and NAT-PMP/PCP forwards can't be listed.
"""

from __future__ import annotations

import html
import ipaddress
import re
import socket
import struct
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field

from .models import Device, Finding
from .protocols import _parse_headers, udp_collect

IGD_TYPES = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
_WAN_SERVICE = re.compile(r"urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:\d")
_MAX_ENTRIES = 256

# Ports that should never be reachable from the internet.
DANGEROUS = {
    21: "FTP", 23: "Telnet", 2323: "Telnet", 135: "Windows RPC", 139: "Windows file sharing",
    445: "Windows file sharing", 3389: "Remote Desktop", 5900: "VNC", 5555: "Android ADB",
    554: "camera video stream (RTSP)", 8554: "camera video stream (RTSP)", 1433: "SQL Server",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch",
    27017: "MongoDB", 7547: "router management (TR-069)", 1900: "UPnP", 34567: "DVR camera",
    37777: "DVR camera",
}
# Types of device that have no business being reachable from the internet.
RISKY_TYPES = {"camera", "microcontroller", "attack_tool", "unknown"}


@dataclass
class PortMapping:
    protocol: str
    external_port: int
    internal_client: str
    internal_port: int
    description: str = ""
    enabled: bool = True
    lease: int = 0  # seconds left; 0 = permanent
    remote_host: str = ""  # empty = anyone on the internet

    def label(self) -> str:
        what = f" ({self.description})" if self.description else ""
        return (f"{self.protocol} {self.external_port} -> {self.internal_client}:"
                f"{self.internal_port}{what}")


@dataclass
class UpnpInfo:
    status: str = "none"  # ok | none (router doesn't offer UPnP) | error
    router: str = ""  # friendly name / model of the gateway device
    control_url: str = ""
    external_ip: str = ""
    mappings: list[PortMapping] = field(default_factory=list)
    natpmp: bool = False  # router also answers NAT-PMP/PCP
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def cgnat(self) -> bool:
        """True when the router's 'internet' address isn't a real public one:
        the ISP shares one address between many homes, so forwards on this
        router usually can't be reached from the internet at all."""
        try:
            ip = ipaddress.ip_address(self.external_ip)
        except ValueError:
            return False
        return ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10")


# ------------------------------------------------------------ discovery


def find_gateway_services(local_ip: str, gateway_ip: str | None,
                          duration: float = 2.5) -> list[str]:
    """LOCATION URLs of UPnP internet-gateway devices that answered."""
    packets = []
    for st in IGD_TYPES:
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               f'MAN: "ssdp:discover"\r\nMX: 2\r\nST: {st}\r\n'
               "USER-AGENT: Noxis/0.1 UPnP/1.1\r\n\r\n").encode()
        packets.append((msg, ("239.255.255.250", 1900)))
        if gateway_ip:  # some routers only answer when asked directly
            packets.append((msg, (gateway_ip, 1900)))
    locations: list[str] = []
    for data, src in udp_collect(packets, local_ip, duration, resend_at=1.0):
        loc = _parse_headers(data.decode("utf-8", "replace")).get("location")
        if loc and loc not in locations and _host_is(loc, src):
            locations.append(loc)
    # The real router first.
    return sorted(locations, key=lambda u: urllib.parse.urlparse(u).hostname != gateway_ip)


def _host_is(url: str, ip: str) -> bool:
    """Only follow a LOCATION that points back at the device that sent it."""
    return urllib.parse.urlparse(url).hostname == ip


def _get(url: str, timeout: float = 3.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Noxis/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (LAN only)
        return resp.read(500_000).decode("utf-8", "replace")


def _tag(xml: str, name: str) -> str:
    m = re.search(rf"<(?:\w+:)?{name}>\s*(.*?)\s*</(?:\w+:)?{name}>", xml, re.S)
    return html.unescape(m.group(1)) if m else ""


def parse_description(xml: str, location: str) -> tuple[str, str, str]:
    """(router name, WAN service type, absolute control URL) from a description."""
    name = " ".join(x for x in (_tag(xml, "manufacturer"), _tag(xml, "modelName")
                                or _tag(xml, "friendlyName")) if x)
    base = _tag(xml, "URLBase") or location
    for block in re.findall(r"<(?:\w+:)?service>(.*?)</(?:\w+:)?service>", xml, re.S):
        stype = _tag(block, "serviceType")
        if _WAN_SERVICE.fullmatch(stype):
            control = urllib.parse.urljoin(base, _tag(block, "controlURL"))
            # Never let a description send us somewhere other than the router.
            if urllib.parse.urlparse(control).hostname == urllib.parse.urlparse(location).hostname:
                return name, stype, control
    return name, "", ""


# ----------------------------------------------------------------- SOAP


class UpnpFault(Exception):
    def __init__(self, code: str, text: str = ""):
        super().__init__(f"UPnP error {code} {text}".strip())
        self.code = code


def soap(control_url: str, service: str, action: str, args: dict | None = None,
         timeout: float = 3.0) -> str:
    body_args = "".join(f"<{k}>{v}</{k}>" for k, v in (args or {}).items())
    body = ('<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service}">{body_args}</u:{action}>'
            "</s:Body></s:Envelope>").encode()
    req = urllib.request.Request(control_url, data=body, method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service}#{action}"',
        "User-Agent": "Noxis/0.1",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (LAN only)
            return resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        text = e.read(20_000).decode("utf-8", "replace")
        raise UpnpFault(_tag(text, "errorCode") or str(e.code), _tag(text, "errorDescription")) from None


def list_mappings(control_url: str, service: str) -> list[PortMapping]:
    out: list[PortMapping] = []
    for i in range(_MAX_ENTRIES):
        try:
            xml = soap(control_url, service, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
        except UpnpFault:
            break  # 713 SpecifiedArrayIndexInvalid = end of the list (others: also stop)
        try:
            out.append(PortMapping(
                protocol=_tag(xml, "NewProtocol").upper() or "?",
                external_port=int(_tag(xml, "NewExternalPort") or 0),
                internal_client=_tag(xml, "NewInternalClient"),
                internal_port=int(_tag(xml, "NewInternalPort") or 0),
                description=_tag(xml, "NewPortMappingDescription")[:80],
                enabled=_tag(xml, "NewEnabled").strip() not in ("0", "false"),
                lease=int(_tag(xml, "NewLeaseDuration") or 0),
                remote_host=_tag(xml, "NewRemoteHost"),
            ))
        except ValueError:
            continue
    return out


# -------------------------------------------------------------- NAT-PMP


def natpmp_answers(gateway_ip: str | None, timeout: float = 1.0) -> bool:
    """Does the router accept NAT-PMP/PCP (another way to open ports)?
    Asks only for the external address, which changes nothing."""
    if not gateway_ip:
        return False
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"\x00\x00", (gateway_ip, 5351))
        data, addr = s.recvfrom(64)
        if addr[0] != gateway_ip or len(data) < 12:
            return False
        _, op, result = struct.unpack("!BBH", data[:4])
        return op == 128 and result == 0
    except OSError:
        return False
    finally:
        s.close()


# ----------------------------------------------------------------- read


def read_port_forwards(local_ip: str, gateway_ip: str | None) -> UpnpInfo:
    info = UpnpInfo(natpmp=natpmp_answers(gateway_ip))
    try:
        locations = find_gateway_services(local_ip, gateway_ip)
    except OSError as e:
        return UpnpInfo(status="error", error=str(e), natpmp=info.natpmp)
    for loc in locations:
        try:
            name, service, control = parse_description(_get(loc), loc)
        except (OSError, ValueError):
            continue
        if not control:
            continue
        info.status, info.router, info.control_url = "ok", name, control
        try:
            info.external_ip = _tag(soap(control, service, "GetExternalIPAddress"),
                                    "NewExternalIPAddress")
        except (UpnpFault, OSError):
            pass
        try:
            info.mappings = list_mappings(control, service)
        except OSError as e:
            info.status, info.error = "error", f"couldn't read the forward list: {e}"
        return info
    return info


# ------------------------------------------------------------ assessment

_LOWER = {"high": "medium", "medium": "low", "low": "low", "info": "info"}


def assess(info: UpnpInfo | None, devices: list[Device] | None,
           gateway_ip: str | None = None):
    """-> (Check, network findings, {device ip: [findings]}).

    `devices` is None when there was no device scan (`noxis check`), so a
    forward to an address can't be matched to a device."""
    from .mitm import Check  # avoid an import cycle at module load

    net: list[Finding] = []
    per_device: dict[str, list[Finding]] = {}
    if info is None:
        return None, net, per_device
    if info.status == "error":
        return Check("Router port forwards", "skip", f"Couldn't read them: {info.error}"), net, per_device
    if info.status != "ok":
        extra = (" It does accept NAT-PMP/PCP requests, another way devices can open ports, "
                 "which Noxis can't list." if info.natpmp else "")
        return Check("Router port forwards", "ok",
                     "Your router doesn't offer UPnP, so devices can't open ports on it by "
                     "themselves. Forwards typed into the router's settings page need its password "
                     "to read, so check those there." + extra), net, per_device

    cg = info.cgnat
    cg_note = (f" Your router's internet address ({info.external_ip}) is shared by your ISP "
               "(CGNAT), so this forward probably isn't reachable from the internet right now, "
               "but it would be if that changes." if cg else "")
    by_ip = {d.ip: d for d in devices or []}
    active = [m for m in info.mappings if m.enabled]

    net.append(Finding(
        "low", "UPnP is on: any device can open ports on your router",
        f"{info.router or 'Your router'} lets any device on the network forward ports from the "
        "internet to itself, with no password and no notice. Games and video calls use this; so "
        "does malware on cameras and smart plugs. Turn UPnP off in the router settings if you "
        "don't need it." + (" The router also accepts NAT-PMP/PCP, which does the same." if info.natpmp else "")))

    for m in info.mappings:
        d = by_ip.get(m.internal_client)
        who = (f"{m.internal_client} ({d.display_name() or d.type_label}"
               f"{', trusted' if d.trusted else ''})" if d else m.internal_client)
        target = f"{m.protocol} port {m.external_port} on the internet goes to {who} port {m.internal_port}"
        desc = f" The program that opened it called it \"{m.description}\"." if m.description else ""
        scope = (f" Only {m.remote_host} can use it." if m.remote_host else " Anyone on the internet can reach it.")
        if not m.enabled:
            continue
        if m.internal_port in DANGEROUS or m.external_port in DANGEROUS:
            svc = DANGEROUS.get(m.internal_port) or DANGEROUS.get(m.external_port)
            sev, title = "high", f"{svc} is exposed to the internet"
            why = (f"{target}. {svc} should never be reachable from the internet: it's one of the "
                   "first things attackers and botnets try.")
        elif d is not None and d.device_type in RISKY_TYPES:
            sev, title = "high", f"{d.type_label} is reachable from the internet"
            why = (f"{target}. Cameras, DIY boards and unidentified devices opening their own "
                   "ports is how many get hijacked, or how a planted device phones home.")
        elif devices is not None and d is None:
            sev, title = "medium", "Port forwarded to a device Noxis can't see"
            why = (f"{target}, but no device answered at that address during the scan. It may be "
                   "asleep, gone (a stale forward), or hiding.")
        elif d is not None and d.trusted:
            sev, title = "low", "Port open to the internet"
            why = f"{target}. Fine if you set this up or recognise the app."
        else:
            sev, title = "medium", "Port open to the internet"
            why = f"{target}. Fine if you recognise it; otherwise find out what opened it."
        if m.lease:
            why += f" It expires in {m.lease // 60} min unless renewed."
        f = Finding(_LOWER[sev] if cg else sev, title, why + desc + scope + cg_note)
        if d is not None:
            per_device.setdefault(d.ip, []).append(f)
        else:
            net.append(f)

    found = [f for fs in per_device.values() for f in fs] + net[1:]
    status = ("fail" if any(f.severity == "high" for f in found)
              else "warn" if active else "ok")
    if active:
        shown = "; ".join(m.label() for m in active[:4]) + ("; ..." if len(active) > 4 else "")
        detail = f"{len(active)} forward(s) opened through UPnP: {shown}"
    else:
        detail = "UPnP is on but nothing is forwarded right now"
    if cg:
        detail += f" (CGNAT: internet address {info.external_ip}, so not reachable from outside)"
    return Check("Router port forwards", status, detail), net, per_device
