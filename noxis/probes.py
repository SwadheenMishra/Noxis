"""Port scanning and service banners (HTTP, RTSP, SSH, Telnet, FTP)."""

from __future__ import annotations

import asyncio
import re
import ssl

from .discovery import tcp_state
from .util import note_failed_connect

PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 81: "HTTP (alt)",
    88: "HTTP (alt)", 139: "NetBIOS", 443: "HTTPS", 445: "SMB file sharing",
    548: "AFP (Mac file sharing)", 554: "RTSP video stream", 631: "IPP printing",
    1400: "Sonos", 1471: "WiFi Pineapple UI", 1883: "MQTT", 1935: "RTMP video",
    2323: "Telnet (alt)", 3000: "HTTP (dev)", 3389: "Remote Desktop",
    4444: "Common backdoor port", 5000: "HTTP / UPnP", 5357: "WSD (Windows)",
    5555: "Android debug (ADB)", 5900: "VNC remote desktop", 6053: "ESPHome API",
    6668: "Tuya smart device", 7000: "AirPlay", 8000: "HTTP (alt) / Hikvision SDK",
    8008: "Chromecast", 8009: "Google Cast", 8080: "HTTP (alt)", 8081: "HTTP (alt)",
    8443: "HTTPS (alt)", 8554: "RTSP video (alt)", 8888: "HTTP (alt)",
    8899: "ONVIF (alt)", 9000: "HTTP (alt)", 9100: "Printer (JetDirect)",
    9527: "Camera control", 31337: "Common backdoor port",
    34567: "XMEye DVR/camera", 37777: "Dahua DVR/camera", 49152: "UPnP / Apple",
    62078: "Apple device sync (iPhone/iPad)",
    # Self-hosted apps, file shares, databases and proxies (services inventory).
    1080: "SOCKS proxy", 1880: "Node-RED", 2049: "NFS file share", 3001: "HTTP (Uptime Kuma)",
    3128: "HTTP proxy (Squid)", 3306: "MySQL", 5001: "HTTPS (Synology)", 5432: "PostgreSQL",
    6052: "ESPHome dashboard", 6379: "Redis", 8006: "Proxmox", 8083: "HTTP (alt)",
    8096: "Jellyfin / Emby", 8112: "Deluge", 8118: "Privoxy", 8123: "Home Assistant",
    8384: "Syncthing", 8920: "Jellyfin (HTTPS)", 9090: "Cockpit / Prometheus",
    9091: "Transmission", 9443: "Portainer (HTTPS)", 10000: "Webmin", 27017: "MongoDB",
    32400: "Plex", 2375: "Docker remote API",
}
QUICK_PORTS = [22, 23, 80, 443, 445, 554, 5555, 8000, 8080, 8554, 34567, 37777, 62078]

HTTP_PORTS = {80, 81, 88, 1471, 1880, 3000, 3001, 3128, 5000, 6052, 8000, 8008, 8080, 8081,
              8083, 8096, 8112, 8118, 8123, 8384, 8888, 8899, 9000, 9090, 9091, 10000, 32400}
TLS_PORTS = {443, 5001, 8006, 8443, 8920, 9443}
RTSP_PORTS = {554, 8554}
BANNER_PORTS = {21, 22, 23, 2323, 3306}
SOCKS_PORTS = {1080}


async def scan_ports(
    ips: list[str], ports: list[int], timeout: float = 1.2, concurrency: int = 300,
    per_host: int = 12, retry_timeout: float | None = 2.5,
) -> dict[str, list[int]]:
    """Connect-scan. Small devices (ESP32s, phones in Wi-Fi power-save) drop
    connections under load or answer slowly, so each host gets a limited
    number of parallel connects, and ports that didn't answer at all are
    retried once with a longer timeout."""
    sem = asyncio.Semaphore(concurrency)
    host_sems = {ip: asyncio.Semaphore(per_host) for ip in ips}

    async def probe(ip, port, t):
        async with host_sems[ip]:
            return await tcp_state(ip, port, t, sem)

    open_ports: dict[str, set[int]] = {ip: set() for ip in ips}
    pairs = [(ip, p) for ip in ips for p in ports]
    for attempt in range(2):
        t = timeout if attempt == 0 else retry_timeout
        states = await asyncio.gather(*(probe(ip, p, t) for ip, p in pairs))
        retry = []
        for (ip, port), state in zip(pairs, states):
            if state == "open":
                open_ports[ip].add(port)
            elif state is None:
                retry.append((ip, port))
        pairs = retry
        if not pairs or retry_timeout is None:
            break
    return {ip: sorted(p) for ip, p in open_ports.items()}


MAX_DEEP_CONNECTIONS = 200  # per device; the default, and the most --deep-connections allows


async def deep_scan(ips: list[str], timeout: float = 0.6, per_host: int = 200,
                    chunk: int = 4096, log=lambda _: None) -> dict[str, list[int]]:
    """Every TCP port (1-65535). About 20s for a device that answers closed
    ports and 3-5 min for one behind a firewall that ignores them, so it's
    opt-in (--deep). Done in chunks to keep memory small."""
    found: dict[str, set[int]] = {ip: set() for ip in ips}
    for start in range(1, 65536, chunk):
        ports = list(range(start, min(start + chunk, 65536)))
        part = await scan_ports(ips, ports, timeout=timeout, concurrency=per_host * len(ips),
                                per_host=per_host, retry_timeout=None)
        for ip, open_ in part.items():
            found[ip] |= set(open_)
        if start // chunk % 4 == 3:
            log(f"  deep scan: {min(start + chunk - 1, 65535) * 100 // 65535}%")
    return {ip: sorted(p) for ip, p in found.items()}


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:  # old cameras/routers only speak ancient TLS
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


async def _exchange(ip: str, port: int, payload: bytes | None, tls: bool = False,
                    limit: int = 65536, timeout: float = 3.0) -> bytes:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=_tls_context() if tls else None), timeout)
    except (asyncio.TimeoutError, OSError):
        note_failed_connect()
        raise
    data = b""
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while len(data) < limit:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            data += chunk
    finally:
        writer.close()
    return data


_BRAND_IN_PAGE = re.compile(
    r"\b(google|gmail|microsoft|outlook|office ?365|facebook|instagram|apple ?id|icloud|paypal|"
    r"amazon|netflix|bank|free ?wi-?fi|wi-?fi login|captive portal|firmware update)\b", re.I)


def parse_http(raw: bytes) -> dict[str, str]:
    text = raw.decode("utf-8", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    info = {"kind": "http"}
    if lines and lines[0].startswith("HTTP/"):
        info["status"] = lines[0][9:].strip()[:60]
    for line in lines[1:]:
        k, _, v = line.partition(":")
        k = k.strip().lower()
        if k == "server":
            info["server"] = v.strip()[:100]
        elif k == "www-authenticate":
            m = re.search(r'realm="?([^",]+)', v, re.I)
            info["realm"] = (m.group(1) if m else v.strip())[:100]
        elif k == "location":
            info["location"] = v.strip()[:150]
        elif k in ("via", "proxy-agent", "x-squid-error"):
            info["via"] = v.strip()[:100]
    # Login forms, and which brand a page claims to be (for phishing pages).
    if re.search(r"type\s*=\s*[\"']?password", body, re.I):
        info["password"] = "yes"
    visible = re.sub(r"<(script|style)\b.*?</\1>|<[^>]+>", " ", body, flags=re.I | re.S)
    brand = _BRAND_IN_PAGE.search(visible)
    if brand:
        info["brand"] = brand.group(0)
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:100]
    return info


async def http_info(ip: str, port: int) -> dict[str, str] | None:
    tls = port in TLS_PORTS
    req = (f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 (Noxis scanner)\r\n"
           "Accept: */*\r\nConnection: close\r\n\r\n").encode()
    try:
        raw = await _exchange(ip, port, req, tls=tls)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    if not raw.startswith(b"HTTP/"):
        return None
    info = parse_http(raw)
    if tls:
        info["tls"] = "yes"
    return info


async def rtsp_info(ip: str, port: int) -> dict[str, str] | None:
    req = (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n"
           "User-Agent: Noxis\r\n\r\n").encode()
    try:
        raw = await _exchange(ip, port, req, limit=4096, timeout=2.5)
    except (OSError, asyncio.TimeoutError):
        return None
    text = raw.decode("utf-8", "replace")
    if not text.startswith("RTSP/"):
        return None
    info = {"kind": "rtsp", "status": text.split("\r\n", 1)[0][9:].strip()[:60]}
    m = re.search(r"^Server:\s*(.+)$", text, re.I | re.M)
    if m:
        info["server"] = m.group(1).strip()[:100]
    return info


def clean_banner(raw: bytes) -> str:
    # Strip telnet IAC negotiation (0xFF cmd opt) and non-printables.
    raw = re.sub(rb"\xff[\xfb-\xfe].|\xff[\xf0-\xfa]", b"", raw)
    text = raw.decode("utf-8", "replace")
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return re.sub(r"\s+", " ", text).strip()[:120]


async def banner_info(ip: str, port: int) -> dict[str, str] | None:
    try:
        raw = await _exchange(ip, port, None, limit=512, timeout=2.5)
    except (OSError, asyncio.TimeoutError):
        return None
    text = clean_banner(raw)
    if not text:
        return None
    return {"kind": "ssh" if text.startswith("SSH-") else "banner", "banner": text}


async def socks_info(ip: str, port: int) -> dict[str, str] | None:
    """SOCKS5 greeting only ('which login methods do you accept?'). The answer
    shows whether it's an open proxy; no connection is ever relayed."""
    try:
        raw = await _exchange(ip, port, b"\x05\x02\x00\x02", limit=2, timeout=2.5)
    except (OSError, asyncio.TimeoutError):
        return None
    if len(raw) == 2 and raw[0] == 5:
        return {"kind": "socks", "auth": {0: "none", 2: "password"}.get(raw[1], "other")}
    return None


async def generic_info(ip: str, port: int) -> dict[str, str] | None:
    """A port Noxis doesn't know (found by --deep): listen for a greeting,
    then try HTTP, which most self-hosted apps speak."""
    return await banner_info(ip, port) or await http_info(ip, port)


async def grab_banners(open_ports: dict[str, list[int]]) -> dict[str, dict[int, dict]]:
    jobs = []
    for ip, ports in open_ports.items():
        for port in ports:
            if port in HTTP_PORTS or port in TLS_PORTS:
                jobs.append((ip, port, http_info(ip, port)))
            elif port in RTSP_PORTS:
                jobs.append((ip, port, rtsp_info(ip, port)))
            elif port in BANNER_PORTS:
                jobs.append((ip, port, banner_info(ip, port)))
            elif port in SOCKS_PORTS:
                jobs.append((ip, port, socks_info(ip, port)))
            elif port not in PORTS:
                jobs.append((ip, port, generic_info(ip, port)))
    results = await asyncio.gather(*(j[2] for j in jobs), return_exceptions=True)
    out: dict[str, dict[int, dict]] = {}
    for (ip, port, _), info in zip(jobs, results):
        if isinstance(info, dict):
            out.setdefault(ip, {})[port] = info
    return out
