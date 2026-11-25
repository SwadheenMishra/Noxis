"""Connection-integrity checks: is anyone sitting between you and the internet?

* HTTPS interception: who signed the certificates of well-known sites?
* DNS hijacking: fake answers for nonexistent names, local addresses for
  public sites, and which DNS server this computer is told to use.
* HTTP tampering: a fixed test page must come back byte-for-byte.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import secrets
import socket
import ssl
import urllib.request
from dataclasses import dataclass

from .models import Finding

HTTPS_SITES = ["www.google.com", "www.microsoft.com", "github.com", "www.wikipedia.org", "www.cloudflare.com"]
DNS_SITES = ["www.google.com", "www.paypal.com", "www.microsoft.com", "www.apple.com"]

PUBLIC_CAS = re.compile(
    r"google trust services|digicert|let's encrypt|internet security research group|sectigo|comodo|"
    r"usertrust|globalsign|amazon|microsoft|entrust|godaddy|starfield|identrust|cloudflare|zerossl|"
    r"buypass|certum|actalis|ssl\.com|telia|quovadis|harica|apple|thawte|geotrust|rapidssl|"
    r"baltimore|cybertrust|verisign|symantec|e-tugra|swisssign|t-systems|deutsche telekom|"
    r"secom|\bisrg\b", re.I)

# (pattern, what it is, severity)
INTERCEPTORS = [
    (r"avast|avg", "Avast/AVG antivirus web shield", "medium"),
    (r"kaspersky", "Kaspersky antivirus", "medium"),
    (r"eset", "ESET antivirus", "medium"),
    (r"bitdefender", "Bitdefender antivirus", "medium"),
    (r"norton|gen digital", "Norton antivirus", "medium"),
    (r"sophos", "Sophos security", "medium"),
    (r"trend ?micro", "Trend Micro security", "medium"),
    (r"fortinet|fortigate", "Fortinet firewall (corporate/school/hotel filter)", "medium"),
    (r"zscaler", "Zscaler corporate proxy", "medium"),
    (r"palo alto", "Palo Alto firewall", "medium"),
    (r"cisco|umbrella", "Cisco firewall / Umbrella", "medium"),
    (r"blue ?coat|symantec web", "Blue Coat proxy", "medium"),
    (r"netskope|forcepoint|websense|check ?point|barracuda|untangle|iboss|cyberoam",
     "corporate web filter", "medium"),
    (r"lightspeed|securly|goguardian|contentkeeper|smoothwall", "school web filter", "medium"),
    (r"mitmproxy|portswigger|burp|fiddler|charles|proxyman|bettercap|sslsplit|owasp zap",
     "a traffic-interception tool", "high"),
    (r"superfish|komodia|privdog|edellroot", "known malicious adware root", "high"),
]


@dataclass
class Check:
    name: str
    status: str  # ok | warn | fail | skip
    detail: str


# ------------------------------------------------------- tiny DER reader

_OID_CN, _OID_O = b"\x55\x04\x03", b"\x55\x04\x0a"


def _tlv(data: bytes, off: int) -> tuple[int, int, int]:
    """Return (tag, value_start, value_end) of the DER element at off."""
    tag = data[off]
    length = data[off + 1]
    off += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[off:off + n], "big")
        off += n
    return tag, off, off + length


def _children(data: bytes, start: int, end: int):
    off = start
    while off < end:
        tag, s, e = _tlv(data, off)
        yield tag, s, e
        off = e


def _name(data: bytes, start: int, end: int) -> dict[str, str]:
    out = {}
    for _, s, e in _children(data, start, end):  # SET
        for _, s2, e2 in _children(data, s, e):  # SEQUENCE {oid, value}
            parts = list(_children(data, s2, e2))
            if len(parts) == 2:
                oid = data[parts[0][1]:parts[0][2]]
                val = data[parts[1][1]:parts[1][2]].decode("utf-8", "replace")
                if oid == _OID_CN:
                    out.setdefault("CN", val)
                elif oid == _OID_O:
                    out.setdefault("O", val)
    return out


def cert_names(der: bytes) -> tuple[dict[str, str], dict[str, str]]:
    """(issuer, subject) of a DER certificate, as {"CN": ..., "O": ...}."""
    _, s, e = _tlv(der, 0)  # Certificate
    _, ts, te = _tlv(der, s)  # tbsCertificate
    fields = list(_children(der, ts, te))
    if fields and fields[0][0] == 0xA0:  # explicit version
        fields = fields[1:]
    # serial, signature algorithm, issuer, validity, subject
    issuer = _name(der, fields[2][1], fields[2][2])
    subject = _name(der, fields[4][1], fields[4][2])
    return issuer, subject


# ----------------------------------------------------------------- HTTPS


def _fetch_cert(host: str, timeout: float = 6) -> tuple[bytes | None, str | None]:
    """Return (DER cert, verification error or None)."""
    raw = ssl.create_default_context()
    raw.check_hostname = False
    raw.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with raw.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host):
                pass
        return der, None
    except ssl.SSLCertVerificationError as e:
        return der, e.verify_message or str(e)


def classify_issuer(issuer: dict[str, str]) -> tuple[str, str | None, str]:
    """-> (status, interceptor name or None, severity)."""
    text = f"{issuer.get('O', '')} {issuer.get('CN', '')}"
    for pattern, what, severity in INTERCEPTORS:
        if re.search(pattern, text, re.I):
            return "intercepted", what, severity
    if PUBLIC_CAS.search(text):
        return "ok", None, "info"
    return "unknown", None, "high"


def check_https(sites=HTTPS_SITES) -> tuple[list[Check], list[Finding]]:
    checks, findings = [], []
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sites)) as pool:
        futs = {pool.submit(_fetch_cert, s): s for s in sites}
        for fut in concurrent.futures.as_completed(futs):
            try:
                results[futs[fut]] = fut.result()
            except (OSError, ssl.SSLError) as e:
                results[futs[fut]] = (None, f"no connection ({e.__class__.__name__})")
    reached = {s: r for s, r in results.items() if r[0]}
    if not reached:
        return [Check("HTTPS interception", "skip", "Couldn't reach any test site (offline?).")], []

    problems = []
    seen_interceptors = {}
    for site in sites:
        if site not in reached:
            continue
        der, verify_error = reached[site]
        try:
            issuer, _ = cert_names(der)
        except (IndexError, ValueError):
            issuer = {}
        who = issuer.get("O") or issuer.get("CN") or "unknown issuer"
        status, interceptor, severity = classify_issuer(issuer)
        if verify_error:
            problems.append(site)
            findings.append(Finding(
                "high", f"Fake certificate for {site}",
                f"{site} presented a certificate from '{who}' that this computer doesn't trust "
                f"({verify_error}). Someone on this network is trying to intercept HTTPS, or a "
                "login page (hotel / captive portal) is getting in the way. Don't enter passwords "
                "on this network."))
        elif status == "intercepted":
            seen_interceptors.setdefault((interceptor, severity, who), []).append(site)
        elif status == "unknown":
            problems.append(site)
            findings.append(Finding(
                "high", f"Unrecognised authority signed {site}",
                f"{site}'s certificate is signed by '{who}', which isn't a public certificate "
                "authority, yet this computer trusts it. A root certificate has probably been "
                "installed on this computer: by spyware, a 'free VPN', or an employer. Check "
                "certmgr.msc > Trusted Root Certification Authorities."))

    for (what, severity, who), hit in seen_interceptors.items():
        problems += hit
        findings.append(Finding(
            severity, f"HTTPS traffic is being decrypted by {what}",
            f"Certificates for {', '.join(hit)} are signed by '{who}' instead of the sites' real "
            "authorities, so it can read your encrypted traffic. "
            + ("That's expected if you installed that antivirus or this is a work/school "
               "network; otherwise treat it as hostile." if severity == "medium" else
               "That's a hacking / debugging proxy: unless you're running it yourself, someone "
               "is intercepting this network.")))
    if problems:
        checks.append(Check("HTTPS interception", "fail",
                            f"{len(set(problems))} of {len(reached)} sites not signed by their real authorities"))
    else:
        checks.append(Check("HTTPS interception", "ok",
                            f"{len(reached)} sites checked, all signed by public certificate authorities"))
    return checks, findings


# ------------------------------------------------------------------- DNS

KNOWN_RESOLVERS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS", "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "76.76.2.0": "Control D", "76.76.10.0": "Control D", "100.100.100.100": "Tailscale MagicDNS",
}


def _resolve(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({i[4][0] for i in infos})


def _reverse(ip: str) -> str:
    """Reverse-DNS name of a server, e.g. dns1.example-isp.net (informational)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def check_dns(dns_servers: list[str], gateway: str | None, known_lan: dict[str, str] | None = None,
              resolve=_resolve, trusted_dns: list[str] | None = None,
              reverse=_reverse) -> tuple[list[Check], list[Finding]]:
    """`known_lan`: trusted devices by IP. `trusted_dns`: DNS servers saved by
    `trust --all`, so Noxis can tell when they change."""
    checks, findings = [], []
    known_lan = known_lan or {}
    trusted_dns = trusted_dns or []
    changed: list[str] = []

    # 1. Which DNS server are we told to use? A rogue DHCP server would push its own.
    if dns_servers:
        labels = []
        for ip in dns_servers:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.is_unspecified:
                continue  # 0.0.0.0: some routers fill an empty DNS slot with it
            if ip == gateway:
                labels.append(f"{ip} (your router)")
            elif ip in KNOWN_RESOLVERS:
                labels.append(f"{ip} ({KNOWN_RESOLVERS[ip]})")
            elif ip in trusted_dns:
                name = reverse(ip)
                labels.append(f"{ip} ({name + ', ' if name else ''}trusted)")
            elif addr.is_private and ip in known_lan:
                labels.append(f"{ip} ({known_lan[ip]}, trusted)")
            elif addr.is_private:
                labels.append(f"{ip} (a device on your network)")
                if trusted_dns:
                    changed.append(ip)
                    continue
                findings.append(Finding(
                    "medium", "DNS goes through another device on the network",
                    f"This computer was told to use {ip} for DNS. That's normal if it's your "
                    "Pi-hole or home server; otherwise a rogue DHCP server may have pushed it so "
                    "it can redirect your browsing."))
            else:
                name = reverse(ip)
                labels.append(f"{ip} ({name or 'unrecognised public server'})")
                if trusted_dns:
                    changed.append(ip)
                    continue
                findings.append(Finding(
                    "low", "Unrecognised DNS server",
                    f"DNS is set to {ip}" + (f" ({name})" if name else "") + ", which isn't your "
                    "router or a well-known resolver. Usually it's your ISP's own server (the name "
                    "often says so). If it's yours, `noxis trust --all` remembers it and Noxis "
                    "will warn you if it ever changes."))
        if changed:
            findings.append(Finding(
                "medium", "DNS server changed",
                f"This network used to give out {', '.join(trusted_dns)} for DNS; now it's "
                f"{', '.join(changed)}. Changing DNS is how malware (DNSChanger-style) and hijacked "
                "routers redirect browsing. Fine if you or your ISP changed it: run "
                "`noxis trust --all` to accept it."))
        checks.append(Check("DNS server", "warn" if findings else "ok", ", ".join(labels)))

    # 2. Names that don't exist must not resolve.
    fake = f"noxis-check-{secrets.token_hex(6)}.com"
    fake_answer = resolve(fake)
    if fake_answer:
        findings.append(Finding(
            "medium", "DNS answers for websites that don't exist",
            f"{fake} doesn't exist, but DNS returned {', '.join(fake_answer)}. Some ISPs do this "
            "to show ad pages; it's also how DNS hijacking looks. Consider setting DNS to "
            "1.1.1.1 or 9.9.9.9."))
        checks.append(Check("Fake-domain test", "warn", f"nonexistent name resolved to {fake_answer[0]}"))
    else:
        checks.append(Check("Fake-domain test", "ok", "nonexistent names correctly don't resolve"))

    # 3. Public sites must not point at local/private addresses.
    bad = {}
    resolved_any = False
    for site in DNS_SITES:
        ips = resolve(site)
        resolved_any |= bool(ips)
        local = [ip for ip in ips if not ipaddress.ip_address(ip).is_global]
        if local:
            bad[site] = local
    if not resolved_any:
        checks.append(Check("DNS answers", "skip", "No answers (offline?)."))
    elif bad:
        for site, ips in bad.items():
            findings.append(Finding(
                "high", f"DNS sends {site} to a local address",
                f"{site} resolved to {', '.join(ips)}, a private address. That's the classic setup "
                "for a fake login page on the local network. Don't log in to anything on this network."))
        checks.append(Check("DNS answers", "fail", f"{len(bad)} public sites point to local addresses"))
    else:
        checks.append(Check("DNS answers", "ok", f"{len(DNS_SITES)} public sites resolve to public addresses"))
    return checks, findings


# ------------------------------------------------------------------ HTTP

CONNECT_TEST = ("http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test")


def check_http(url: str = CONNECT_TEST[0], expected: str = CONNECT_TEST[1]) -> tuple[list[Check], list[Finding]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Noxis)"})
        with urllib.request.urlopen(req, timeout=6) as resp:  # noqa: S310
            final, body = resp.geturl(), resp.read(4096).decode("utf-8", "replace")
    except OSError as e:
        return [Check("HTTP tampering", "skip", f"Test page unreachable ({e.__class__.__name__}).")], []
    if body.strip() == expected and final == url:
        return [Check("HTTP tampering", "ok", "unencrypted test page arrived unmodified")], []
    where = f" (redirected to {final})" if final != url else ""
    return ([Check("HTTP tampering", "fail", f"test page was altered{where}")],
            [Finding("medium", "Unencrypted web traffic is being altered",
                     f"A fixed test page came back different{where}. Usually a captive portal "
                     "(hotel/café login page) or an ISP injecting content; on a home network it "
                     "can mean someone is tampering with traffic.")])


# ------------------------------------------------------------------- all


def run_checks(dns_servers: list[str], gateway: str | None,
               known_lan: dict[str, str] | None = None,
               trusted_dns: list[str] | None = None) -> tuple[list[Check], list[Finding]]:
    checks, findings = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        jobs = [pool.submit(check_https), pool.submit(check_dns, dns_servers, gateway, known_lan, _resolve, trusted_dns),
                pool.submit(check_http)]
        for job in jobs:
            c, f = job.result()
            checks += c
            findings += f
    return checks, findings
