"""What each device is hosting: web apps, media servers, file shares, proxies.

A port number alone says little (8080 is used by a hundred things), so each
service is identified from what it says about itself: web page titles,
server headers, SSH/FTP banners. Each one gets a *fingerprint*: a
version-free identity string. A trusted service whose fingerprint changes
(your landing page turning into a login form, say) is worth an alert even
though the port didn't change.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .models import Device, Finding

# (name, category, ports it usually lives on, regex over title/server/realm/banner)
SIGNATURES: list[tuple[str, str, set[int], str]] = [
    ("Jellyfin", "media", {8096, 8920}, r"jellyfin"),
    ("Emby", "media", {8096, 8920}, r"\bemby\b"),
    ("Plex", "media", {32400}, r"\bplex\b"),
    ("Kodi", "media", set(), r"\bkodi\b"),
    ("Navidrome", "media", {4533}, r"navidrome"),
    ("Home Assistant", "smart home", {8123}, r"home assistant"),
    ("Node-RED", "smart home", {1880}, r"node-red"),
    ("ESPHome", "smart home", {6052}, r"esphome"),
    ("Zigbee2MQTT", "smart home", set(), r"zigbee2mqtt"),
    ("Pi-hole", "network", set(), r"pi-hole|pihole"),
    ("AdGuard Home", "network", {3000}, r"adguard"),
    ("Portainer", "admin", {9000, 9443}, r"portainer"),
    ("Proxmox", "admin", {8006}, r"proxmox"),
    ("Cockpit", "admin", {9090}, r"cockpit"),
    ("Webmin", "admin", {10000}, r"webmin|miniserv"),
    ("Uptime Kuma", "admin", {3001}, r"uptime kuma"),
    ("Grafana", "admin", {3000}, r"grafana"),
    ("Prometheus", "admin", {9090}, r"prometheus"),
    ("Nextcloud", "files", set(), r"nextcloud"),
    ("Syncthing", "files", {8384}, r"syncthing"),
    ("Synology DSM", "files", {5001}, r"synology|diskstation"),
    ("qBittorrent", "downloads", set(), r"qbittorrent"),
    ("Transmission", "downloads", {9091}, r"transmission"),
    ("Deluge", "downloads", {8112}, r"\bdeluge\b"),
    ("Vaultwarden", "passwords", set(), r"vaultwarden|bitwarden"),
    ("Gitea", "dev", set(), r"\bgitea\b|forgejo"),
    ("Jenkins", "dev", set(), r"jenkins"),
    ("Jupyter", "dev", {8888}, r"jupyter"),
    ("OctoPrint", "3D printing", set(), r"octoprint"),
    ("CUPS printing", "printer", {631}, r"\bcups\b"),
    ("Hikvision camera", "camera", set(), r"hikvision|dnvrs-webs|app-webs"),
    ("Dahua camera", "camera", set(), r"dahua|web service.*dvr"),
    ("XMEye / NETSurveillance camera", "camera", set(), r"netsurveillance|uc-httpd|xmeye"),
    ("ESP32-CAM", "camera", set(), r"esp32-?cam|cameraweb"),
    ("mitmproxy (traffic interception)", "interception", {8080, 8081}, r"mitmproxy|mitmweb"),
    ("Burp Suite (traffic interception)", "interception", set(), r"burp suite|burp"),
    ("Bettercap (attack tool)", "interception", {8083}, r"bettercap"),
    ("WiFi Pineapple", "interception", {1471}, r"pineapple"),
    ("Squid proxy", "proxy", {3128}, r"squid"),
    ("Tinyproxy", "proxy", {8888}, r"tinyproxy"),
    ("Privoxy", "proxy", {8118}, r"privoxy"),
    ("nginx default page", "web", set(), r"welcome to nginx"),
    ("Apache default page", "web", set(), r"apache2? .*default page|^it works!?$"),
]

def _port_hints() -> dict[int, tuple[str, str]]:
    """A web server with no title on a port only one app uses: 'Probably Jellyfin'.
    Never guesses attack tools or proxies, which would be false alarms."""
    owners: dict[int, list[tuple[str, str]]] = {}
    for name, cat, ports, _ in SIGNATURES:
        for p in ports:
            owners.setdefault(p, []).append((name, cat))
    hints = {}
    for p, o in owners.items():
        cats = {c for _, c in o}
        if len(cats) == 1 and not cats & {"interception", "proxy"}:
            hints[p] = ("Probably " + " / ".join(n for n, _ in o), o[0][1])
    return hints


# Services that aren't web pages, named from the port (and banner when there is one).
PORT_SERVICES: dict[int, tuple[str, str]] = {
    21: ("FTP", "files"), 22: ("SSH", "remote access"), 23: ("Telnet", "remote access"),
    2323: ("Telnet", "remote access"), 53: ("DNS server", "network"),
    139: ("Windows file sharing (NetBIOS)", "files"), 445: ("Windows file sharing (SMB)", "files"),
    548: ("Mac file sharing (AFP)", "files"), 2049: ("NFS file share", "files"),
    554: ("Camera video stream (RTSP)", "camera"), 8554: ("Camera video stream (RTSP)", "camera"),
    631: ("Printing (IPP)", "printer"), 9100: ("Printing (JetDirect)", "printer"),
    1080: ("SOCKS proxy", "proxy"), 1883: ("MQTT broker", "smart home"),
    3306: ("MySQL database", "database"), 5432: ("PostgreSQL database", "database"),
    6379: ("Redis database", "database"), 27017: ("MongoDB database", "database"),
    3389: ("Remote Desktop", "remote access"), 5900: ("VNC remote desktop", "remote access"),
    5555: ("Android debugging (ADB)", "remote access"), 6053: ("ESPHome API", "smart home"),
    6668: ("Tuya smart device", "smart home"), 7000: ("AirPlay", "media"),
    8008: ("Chromecast", "media"), 8009: ("Google Cast", "media"), 1400: ("Sonos", "media"),
    62078: ("iPhone/iPad sync", "device"), 5357: ("Windows device discovery (WSD)", "device"),
    34567: ("XMEye DVR/camera control", "camera"), 37777: ("Dahua DVR/camera control", "camera"),
    4444: ("Common backdoor port", "suspicious"), 31337: ("Common backdoor port", "suspicious"),
    # Ones a --deep scan typically turns up.
    25: ("Mail server (SMTP)", "mail"), 110: ("Mail (POP3)", "mail"), 143: ("Mail (IMAP)", "mail"),
    111: ("RPC portmapper (rpcbind, used by NFS)", "files"), 389: ("LDAP directory", "admin"),
    873: ("rsync file sync", "files"), 2375: ("Docker remote API", "admin"),
    2376: ("Docker remote API (TLS)", "admin"), 4369: ("Erlang port mapper", "dev"),
    5353: ("Bonjour / mDNS", "device"), 5672: ("RabbitMQ", "dev"), 6443: ("Kubernetes API", "admin"),
    9092: ("Kafka", "dev"), 10250: ("Kubernetes kubelet", "admin"), 11211: ("Memcached", "database"),
}

# Login pages imitating these, served from a device on your network, are phishing.
BRANDS = re.compile(
    r"\b(google|gmail|microsoft|outlook|office ?365|hotmail|facebook|instagram|whatsapp|"
    r"apple ?id|icloud|paypal|amazon|netflix|steam|discord|bank|sbi|hdfc|icici|paytm|"
    r"free ?wi-?fi|wi-?fi login|guest wi-?fi|captive portal|firmware update|router update)\b", re.I)


@dataclass
class Service:
    port: int
    name: str
    category: str
    detail: str = ""  # title / server / banner, as shown to the user
    fingerprint: str = ""  # version-free identity, for change detection
    login_form: bool = False
    nickname: str = ""
    trusted: bool = False

    def label(self) -> str:
        base = self.nickname or self.name
        return f"{base} ({self.detail})" if self.detail and self.detail not in base else base

    def to_dict(self) -> dict:
        return asdict(self)


def _short_banner(text: str) -> str:
    """'220 localhost FTP server (GNU inetutils 1.9.4) ready.' -> 'GNU inetutils 1.9.4'."""
    m = re.search(r"\(([^)]{3,60})\)", text)
    if m:
        return m.group(1)
    text = re.sub(r"^\d{3}[\s-]+|\s*ready\.?$", "", text, flags=re.I)
    return text[:60]


def _no_versions(text: str) -> str:
    """'nginx/1.22.1' and 'nginx/1.24.0' are the same service."""
    return re.sub(r"[\s/_-]*v?\d+(?:[.\-_p]\d+)*\w*", "", text or "").strip().lower()


def identify(port: int, banner: dict | None) -> Service:
    b = banner or {}
    title, server = b.get("title", ""), b.get("server", "")
    redirect = (b.get("status") or "")[:1] == "3"
    if redirect and re.match(r"\d{3}\b|moved|found|redirect", title, re.I):
        title = ""  # "302 Moved Temporarily" is the redirect's title, not the site's
    realm, text = b.get("realm", ""), b.get("banner", "")
    haystack = " | ".join(x for x in (title, server, realm, text, b.get("brand", "")) if x)

    for name, cat, ports, pattern in SIGNATURES:
        if re.search(pattern, haystack, re.I):
            break
    else:
        name = cat = None

    kind = b.get("kind")
    if name is None and kind == "http" and not title and port in _PORT_HINTS:
        name, cat = _PORT_HINTS[port]
    if name is None:
        if kind == "ssh":
            m = re.match(r"SSH-[\d.]+-(\S+)", text)
            soft = m.group(1).replace("_", " ") if m else ""
            name, cat = (f"SSH ({soft})" if soft else "SSH"), "remote access"
        elif kind == "socks":
            name, cat = ("Open SOCKS proxy" if b.get("auth") == "none" else "SOCKS proxy"), "proxy"
        elif kind == "rtsp":
            name, cat = "Camera video stream (RTSP)", "camera"
        elif kind == "http" and title:
            name, cat = f"Web page \"{title}\"", "web"
        elif kind == "http":
            name, cat = (f"Web server ({server})" if server else "Web server"), "web"
        elif port in PORT_SERVICES:
            name, cat = PORT_SERVICES[port]
        elif text:
            name, cat = f"Service on port {port}", "other"
        else:
            name, cat = f"Unknown service on port {port}", "other"
    if kind == "http" and b.get("via"):
        cat = "proxy" if cat == "web" else cat

    detail_bits = [x for x in (title if title and title not in name else "",
                               server if server and server not in name else "",
                               _short_banner(text) if kind == "banner" else "",
                               f"redirects to {b['location'][:60]}" if redirect and b.get("location") else "")
                   if x]
    fingerprint = "|".join(["web page" if name.startswith("Web page") else _no_versions(name),
                            _no_versions(title), _no_versions(server.split(" ")[0]),
                            _no_versions(text.split(" ")[0]) if kind in ("ssh", "banner") else ""])
    return Service(port=port, name=name, category=cat, detail=", ".join(detail_bits)[:100],
                   fingerprint=fingerprint, login_form=bool(b.get("password")))


def identify_all(d: Device) -> list[Service]:
    return [identify(p, d.banners.get(p)) for p in d.open_ports]


# ------------------------------------------------------------ assessment


def _impersonated_brand(s: Service, banner: dict | None) -> str | None:
    if not s.login_form:
        return None
    m = BRANDS.search(" ".join(x for x in ((banner or {}).get("title", ""), (banner or {}).get("brand", "")) if x))
    return m.group(0) if m else None


def assess(d: Device) -> list[Finding]:
    """Risky services on one device, plus changes to services you trusted."""
    out: list[Finding] = []
    profile = (d.trusted_profile or {}).get("services") or {}
    for s in d.services:
        saved = profile.get(str(s.port))
        if saved:
            s.trusted = saved.get("id") == s.fingerprint
            s.nickname = saved.get("name") or ""
        if s.trusted:
            continue
        b = d.banners.get(s.port)
        where = f"port {s.port} on {d.ip}"
        brand = _impersonated_brand(s, b)
        if brand and not d.is_gateway:
            out.append(Finding(
                "high", f"Fake {brand.title()} login page",
                f"{where} serves a sign-in page that mentions '{brand}'. Real {brand} logins never "
                "come from a device on your Wi-Fi, so this is phishing, e.g. an 'evil portal' "
                "on an ESP32 or WiFi Pineapple collecting passwords. Don't type anything into it."))
        elif s.category == "interception":
            out.append(Finding(
                "high", f"{s.name} on the network",
                f"{where} is running {s.name}. These tools sit between devices and the internet to "
                "read or change traffic. Fine on your own test box; otherwise someone is attacking "
                "this network."))
        elif s.port == 2375:
            out.append(Finding(
                "high", "Docker remote API open without a password",
                f"{where} accepts Docker commands with no login. Anyone on this network can use it "
                "to run any program as root on that machine. Bind it to localhost or use TLS (2376)."))
        elif s.category == "proxy" and not d.trusted:
            out.append(Finding(
                "medium", f"{s.name} on {d.ip}",
                f"{where} relays traffic for others. People run these to route their browsing or "
                "attacks through your internet connection, or to snoop on whoever uses it."))
        elif s.port == 53 and not d.is_gateway and not d.trusted:
            out.append(Finding(
                "medium", "DNS server on a device that isn't your router",
                f"{d.ip} answers DNS. Normal for a Pi-hole or AdGuard box; otherwise it can be "
                "used, with a rogue DHCP server, to redirect everyone's browsing."))
        if saved and not s.trusted:
            old = saved.get("name") or saved.get("label") or "something else"
            out.append(Finding(
                "medium", "Trusted service changed",
                f"Port {s.port} used to be {old}; now it's {s.label()}. Fine after an update or a "
                f"new app; otherwise the device may have been tampered with. To accept it: "
                f"noxis trust {d.ip}:{s.port}"))
    return out


def new_services_text(d: Device, ports: list[int]) -> str:
    by_port = {s.port: s for s in d.services}
    return "; ".join(f"{p}: {by_port[p].label()}" if p in by_port else str(p) for p in ports)


def snapshot(services: list[dict]) -> dict:
    """What `noxis trust` saves for a device's services (from last_scan.json)."""
    return {str(s["port"]): {"id": s["fingerprint"], "label": s["name"], "name": s.get("nickname", "")}
            for s in services}


_PORT_HINTS = _port_hints()
