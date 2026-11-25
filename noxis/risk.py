"""Turn classified devices into security findings."""

from __future__ import annotations

from collections import defaultdict

from . import services
from .models import Device, Finding, ScanResult

_RISKY_PORTS = {
    23: ("high", "Telnet is open",
         "Telnet sends logins in plain text and is the main way IoT botnets (e.g. Mirai) break in. "
         "Disable it, or remove the device if you can't."),
    2323: ("high", "Telnet (alt port 2323) is open",
           "Alternate Telnet port often left open on cheap IoT devices and botnet-infected hosts."),
    5555: ("high", "Android debugging (ADB) is open to the network",
           "Anyone on the network can install apps or take control. Turn off 'ADB over network' / "
           "wireless debugging, or remove the device."),
    4444: ("high", "Port 4444 is open (common backdoor / Metasploit listener)",
           "Rarely legitimate. Investigate what is listening on this device."),
    31337: ("high", "Port 31337 is open (classic backdoor port)",
            "Rarely legitimate. Investigate what is listening on this device."),
    1471: ("high", "WiFi Pineapple management port is open",
           "Port 1471 is the web UI of the Hak5 WiFi Pineapple, a rogue access point / MITM tool."),
    21: ("low", "FTP is open", "FTP sends passwords unencrypted."),
    3389: ("low", "Remote Desktop is open", "Fine if intentional; make sure it uses a strong password."),
    5900: ("low", "VNC remote desktop is open", "VNC is often set up with weak or no passwords."),
}


def _type_findings(d: Device) -> list[Finding]:
    why = "; ".join(d.evidence)
    t = d.device_type
    out: list[Finding] = []
    if t == "camera":
        out.append(Finding(
            "high", "Possible camera or video recorder",
            f"Why: {why}. If you don't know about this camera, look for it physically (smoke "
            "detectors, clocks, USB chargers, anything facing beds or bathrooms). In a rental, "
            "indoor cameras break Airbnb policy, so photograph it and report it."))
    elif t == "microcontroller":
        out.append(Finding(
            "medium", "Unidentified microcontroller board",
            f"Why: {why}. ESP32/ESP8266 boards are in plenty of legit smart plugs and DIY projects, "
            "but also in Wi-Fi sniffers, deauthers and tiny cameras (ESP32-CAM). If it's not yours, "
            "find it or block it on the router."))
    elif t == "sbc":
        out.append(Finding(
            "medium", "Single-board computer (Raspberry Pi-style)",
            f"Why: {why}. These run full Linux and are a classic covert 'drop box' for attackers. "
            "Fine if it's your Pi-hole, Home Assistant or project box."))
    elif t == "attack_tool":
        out.append(Finding(
            "high", "Possible hacking / pentest device",
            f"Why: {why}. Unless you or your IT team put it there, treat this as hostile: disconnect "
            "from this network and change your passwords from a different network."))
    elif t == "unknown":
        out.append(Finding(
            "low", "Couldn't identify this device",
            "It answered on the network but gave no clues about what it is. Check your router's "
            "client list, or block it if you don't recognise it."))

    cam_score = d.type_scores.get("camera", 0)
    if t != "camera" and cam_score >= 35:
        out.append(Finding(
            "medium", "Has camera-like traits",
            "Some clues point to a camera even though another type scored higher: "
            "check what it is."))
    if t != "camera" and any(p in d.open_ports for p in (554, 8554)):
        out.append(Finding(
            "medium", "Video-streaming (RTSP) port is open",
            "RTSP is almost only used by cameras and video recorders."))
    return out


_SHARP_PORTS = {23, 2323, 5555, 4444, 31337, 1471, 554, 8554, 34567, 37777}


def _profile_findings(d: Device) -> list[Finding]:
    """Compare a trusted device with the fingerprint saved when it was trusted.
    A copied MAC gives the impostor the trust, but not the same behaviour."""
    p = d.trusted_profile
    if not p or not d.trusted:
        return []
    out = []
    old_type = p.get("type")
    if (old_type and old_type != "unknown" and d.device_type not in ("unknown", old_type)
            and d.confidence in ("medium", "high")):
        out.append(Finding(
            "high", "Trusted device now looks like a different device",
            f"When you trusted {d.mac} it was identified as {old_type}; now it looks like "
            f"{d.device_type} ({'; '.join(d.evidence)}). Someone may have copied its MAC to "
            "borrow its trust. If you changed the device's firmware, re-run `noxis trust`."))
    new_ports = sorted(set(d.open_ports) - set(p.get("ports") or []))
    if new_ports:
        sharp = [x for x in new_ports if x in _SHARP_PORTS]
        out.append(Finding(
            "high" if sharp else "medium", "New service on a trusted device",
            f"Not running when you trusted it: {services.new_services_text(d, new_ports)}. "
            "Could be an update or something you set up, or a different device using its MAC. "
            f"If it's yours: noxis trust {d.ip}:{new_ports[0]} --name \"...\" (or `noxis trust "
            f"{d.ip}` for all of them)."))
    return out


def assess_device(d: Device, baseline_exists: bool) -> None:
    d.findings = []
    if d.is_self:
        return
    if not d.trusted and not d.is_gateway:
        d.findings += _type_findings(d)
    d.findings += _profile_findings(d)
    d.findings += services.assess(d)

    for port, (sev, title, detail) in _RISKY_PORTS.items():
        if port in d.open_ports:
            if d.trusted and sev != "high":
                continue
            d.findings.append(Finding(sev, title, detail))

    if baseline_exists and not d.trusted and not d.is_gateway:
        detail = ("This device isn't in your trusted list for this network"
                  + (" and has never been seen here before." if d.first_seen_now else ".")
                  + f" If it's yours: noxis trust {d.ip} --name \"...\"")
        d.findings.append(Finding("medium", "Not in your trusted devices", detail))

    if d.randomized_mac and not d.trusted and d.device_type in ("unknown", "phone"):
        d.findings.append(Finding(
            "info", "Uses a private (randomized) MAC",
            "The manufacturer is hidden. Most likely a phone, tablet or laptop with "
            "'private Wi-Fi address' turned on."))


def assess_network(result: ScanResult, previous_gateway_mac: str | None) -> None:
    net = result.network
    findings: list[Finding] = []

    by_mac: dict[str, list[str]] = defaultdict(list)
    for d in result.devices:
        if d.mac and not d.is_self:
            by_mac[d.mac].append(d.ip)
    for mac, ips in by_mac.items():
        if len(ips) > 1:
            gw = net.gateway_ip in ips
            findings.append(Finding(
                "high" if gw else "medium",
                "One device is answering for several IP addresses" + (" including the router" if gw else ""),
                f"MAC {mac} claims {', '.join(sorted(ips))}. This is how ARP-spoofing (man-in-the-middle) "
                "attacks look. Wi-Fi range extenders can also cause it; if you don't have one, "
                "disconnect and investigate."))

    if previous_gateway_mac and net.gateway_mac and previous_gateway_mac != net.gateway_mac:
        findings.append(Finding(
            "high", "The router's hardware address changed",
            f"Last time the gateway {net.gateway_ip} was {previous_gateway_mac}, now it's "
            f"{net.gateway_mac}. Expected if the router was replaced; otherwise it may be an "
            "impostor (ARP spoofing / evil-twin network)."))

    others = [d for d in result.devices if not d.is_self and not d.is_gateway]
    if not others:
        findings.append(Finding(
            "medium", "No other devices are visible. Some may be hidden",
            "This network seems to isolate Wi-Fi clients from each other, so cameras or other "
            "devices could be connected without showing up here. Check the router's client list, "
            "and do a physical check."))

    if not result.baseline_exists:
        findings.append(Finding(
            "info", "No trusted baseline yet for this network",
            "Once you've checked the devices above are yours, run `noxis trust --all`. "
            "Future scans will then flag anything new."))
    if "IEEE" not in result.oui_sources:
        findings.append(Finding(
            "info", "Manufacturer list is limited",
            "Run `noxis update-oui` once to download the full IEEE manufacturer registry so more "
            "devices get identified."))
    result.findings = findings
