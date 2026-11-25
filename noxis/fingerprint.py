"""Work out what each device *is* from the evidence the scan collected.

Every clue (MAC vendor, open ports, mDNS services, UPnP model, ONVIF reply,
HTTP page titles, hostnames, TTL...) adds points to one or more device types.
The highest-scoring type wins; the clues behind it become the "evidence"
shown to the user.
"""

from __future__ import annotations

import re
from collections import defaultdict

from .models import Device
from .util import IS_MAC, IS_WINDOWS

TYPE_LABELS = {
    "router": "Router / gateway",
    "network": "Network gear (AP / mesh / switch)",
    "computer_windows": "Windows computer",
    "computer_mac": "Mac",
    "computer_linux": "Linux computer",
    "computer": "Computer",
    "phone_apple": "iPhone / iPad",
    "phone_android": "Android phone / tablet",
    "phone": "Phone or tablet",
    "apple": "Apple device",
    "camera": "IP camera / video recorder",
    "microcontroller": "Microcontroller (ESP32 / ESP8266 / Arduino)",
    "sbc": "Single-board computer (Raspberry Pi etc.)",
    "speaker": "Smart speaker / audio",
    "tv": "TV / streaming device",
    "printer": "Printer / scanner",
    "nas": "NAS / file server",
    "iot": "Smart-home / IoT device",
    "console": "Game console",
    "attack_tool": "Hacking / pentest device",
    "unknown": "Unknown device",
}

# (regex, type, weight, reason) - matched against the MAC vendor name.
VENDOR_RULES = [
    (r"espressif", "microcontroller", 45, "Espressif chip (ESP32/ESP8266): DIY boards and cheap smart gadgets"),
    (r"arduino", "microcontroller", 60, "Made by Arduino"),
    (r"raspberry", "sbc", 60, "Made by Raspberry Pi"),
    (r"seeed|adafruit|hardkernel|radxa|xunlong", "sbc", 40, "Maker-board manufacturer"),
    (r"hikvision|dahua|amcrest|reolink|baichuan|wyze|foscam|ezviz|vivotek|axis comm|hanwha|"
     r"uniview|lorex|swann|arlo|imou|xiongmai|tvt digital|geovision|milesight",
     "camera", 60, "Made by a camera / surveillance manufacturer"),
    (r"^ring( llc)?$", "camera", 40, "Made by Ring (doorbells / cameras)"),
    (r"apple", "apple", 40, "Made by Apple"),
    (r"samsung|xiaomi|oneplus|oppo|vivo mobile|motorola mobility|huawei device|honor device",
     "phone", 15, "Phone manufacturer"),
    (r"intel|liteon|lite-on|azurewave|hon hai|foxconn|chicony|dell|lenovo|asustek|micro-star|"
     r"gigabyte|rivet|framework|realtek|compal|quanta|wistron|cloud network technology",
     "computer", 25, "Network chip / maker common in laptops and PCs"),
    (r"brother|canon|seiko epson|xerox|lexmark|kyocera|ricoh", "printer", 50, "Printer manufacturer"),
    (r"synology|qnap|western digital|asustor", "nas", 50, "NAS manufacturer"),
    (r"sonos|bose|harman|denon|bang & olufsen", "speaker", 50, "Audio equipment maker"),
    (r"roku|vizio|hisense|tcl", "tv", 40, "TV / streaming maker"),
    (r"nintendo|sony interactive", "console", 60, "Game console maker"),
    (r"amazon", "iot", 25, "Amazon device (Echo, Fire TV, Ring, Kindle...)"),
    (r"google|nest labs", "iot", 25, "Google / Nest device"),
    (r"philips lighting|signify|lifx|tuya|shelly|allterco|itead|sonoff|ecobee|irobot|wink|"
     r"meross|belkin|lutron|bilian|bouffalo|beken|tp-link|broadlink",
     "iot", 35, "Smart-home / IoT maker"),
    (r"ubiquiti|netgear|linksys|d-link|tenda|mikrotik|routerboard|eero|cisco|aruba|juniper|zyxel|"
     r"sagemcom|technicolor|arris|huawei tech|zte|nokia|tp-link|asus|syrotech|netlink ict|"
     r"digisol|genexis|fiberhome",
     "network", 20, "Networking equipment maker"),
    (r"hak5", "attack_tool", 90, "Made by Hak5 (pentest hardware)"),
]

# Matched against hostnames, NetBIOS names, mDNS instance names, UPnP names.
NAME_RULES = [
    (r"iphone|ipad", "phone_apple", 60, "Name says iPhone/iPad"),
    (r"macbook|imac|mac-?mini|mac-?pro|mac-?studio", "computer_mac", 60, "Name says Mac"),
    (r"apple-?tv", "tv", 60, "Name says Apple TV"),
    (r"homepod", "speaker", 60, "Name says HomePod"),
    (r"android|galaxy|pixel|oneplus|redmi|\bsm-[a-z]\d", "phone_android", 45, "Name looks like an Android phone"),
    (r"^desktop-|^laptop-|-pc$|windows", "computer_windows", 40, "Windows-style computer name"),
    (r"raspberrypi|raspberry|\brpi\d?\b|\brp[345]\b|\bpi[345]\b|octopi|pi-?hole", "sbc", 55,
     "Name says Raspberry Pi"),
    (r"esp32|esp8266|esp-|espressif|esphome|tasmota|wled|arduino|nodemcu|wemos|ttgo|lilygo|m5stack",
     "microcontroller", 55, "Name looks like a microcontroller board"),
    (r"camera|\bcam\b|ipcam|webcam|\bipc\b|ipc-|\bdvr\b|\bnvr\b|hikvision|dahua|reolink|wyze|"
     r"tapo-?c\d|doorbell|blink|esp32-?cam",
     "camera", 45, "Name looks like a camera"),
    (r"chromecast|roku|fire-?tv|bravia|smart-?tv|webos|tizen|shield", "tv", 50, "Name looks like a TV / streamer"),
    (r"\becho\b|alexa|google-?home|nest-?(mini|hub|audio)|sonos", "speaker", 50, "Name looks like a smart speaker"),
    (r"printer|laserjet|officejet|deskjet|epson|brother|canon", "printer", 50, "Name looks like a printer"),
    (r"synology|diskstation|qnap|\bnas\b|truenas", "nas", 50, "Name looks like a NAS"),
    (r"xbox|playstation|\bps[45]\b|nintendo", "console", 45, "Name looks like a game console"),
    (r"pineapple|hak5|flipper|\bkali\b|parrot-?os|pwnagotchi", "attack_tool", 60, "Name matches a hacking tool / OS"),
]

PORT_RULES = {
    62078: ("phone_apple", 70, "Apple device-sync port 62078 open (iPhone/iPad)"),
    445: ("computer", 25, "SMB file sharing open"),
    139: ("computer_windows", 20, "NetBIOS open"),
    3389: ("computer_windows", 45, "Remote Desktop (RDP) open"),
    5357: ("computer_windows", 35, "Windows WSD service open"),
    548: ("computer_mac", 40, "Mac file sharing (AFP) open"),
    554: ("camera", 50, "RTSP video-stream port 554 open"),
    8554: ("camera", 40, "RTSP video-stream port 8554 open"),
    37777: ("camera", 70, "Dahua DVR/camera port 37777 open"),
    34567: ("camera", 70, "XMEye DVR/camera port 34567 open"),
    9527: ("camera", 30, "Port 9527 open (cheap camera control)"),
    8899: ("camera", 20, "Port 8899 open (ONVIF on some cameras)"),
    1935: ("camera", 20, "RTMP video port open"),
    9100: ("printer", 50, "Printer port 9100 open"),
    631: ("printer", 35, "IPP printing open"),
    1400: ("speaker", 50, "Sonos port 1400 open"),
    8008: ("tv", 35, "Chromecast port 8008 open"),
    8009: ("tv", 35, "Google Cast port 8009 open"),
    6668: ("iot", 50, "Tuya smart-device port 6668 open"),
    6053: ("microcontroller", 65, "ESPHome API port 6053 open"),
    5555: ("phone_android", 25, "Android debug port open"),
    1883: ("iot", 15, "MQTT broker open"),
    1471: ("attack_tool", 70, "WiFi Pineapple management port 1471 open"),
}

MDNS_RULES = {
    "_airplay._tcp": ("apple", 30, "Advertises AirPlay"),
    "_raop._tcp": ("apple", 20, "Advertises AirPlay audio"),
    "_companion-link._tcp": ("apple", 40, "Advertises Apple Companion Link"),
    "_apple-mobdev2._tcp": ("phone_apple", 60, "Advertises Apple mobile-device sync"),
    "_rdlink._tcp": ("apple", 30, "Advertises Apple remote link"),
    "_googlecast._tcp": ("tv", 55, "Advertises Google Cast"),
    "_amzn-wplay._tcp": ("tv", 45, "Advertises Amazon Fire TV"),
    "_androidtvremote2._tcp": ("tv", 55, "Advertises Android TV remote"),
    "_sonos._tcp": ("speaker", 70, "Advertises Sonos"),
    "_spotify-connect._tcp": ("speaker", 25, "Advertises Spotify Connect"),
    "_hap._tcp": ("iot", 45, "HomeKit accessory"),
    "_homekit._tcp": ("iot", 30, "HomeKit"),
    "_matter._tcp": ("iot", 30, "Matter smart-home device"),
    "_matterc._udp": ("iot", 30, "Matter smart-home device"),
    "_esphomelib._tcp": ("microcontroller", 75, "Advertises ESPHome"),
    "_arduino._tcp": ("microcontroller", 75, "Advertises Arduino OTA"),
    "_wled._tcp": ("microcontroller", 70, "Advertises WLED (ESP LED controller)"),
    "_shelly._tcp": ("iot", 65, "Shelly smart relay"),
    "_miio._udp": ("iot", 50, "Xiaomi smart-home device"),
    "_rtsp._tcp": ("camera", 55, "Advertises an RTSP video stream"),
    "_printer._tcp": ("printer", 60, "Advertises a printer"),
    "_ipp._tcp": ("printer", 50, "Advertises IPP printing"),
    "_ipps._tcp": ("printer", 50, "Advertises IPP printing"),
    "_pdl-datastream._tcp": ("printer", 60, "Advertises raw printing"),
    "_scanner._tcp": ("printer", 30, "Advertises a scanner"),
    "_afpovertcp._tcp": ("computer_mac", 40, "Advertises Mac file sharing"),
    "_smb._tcp": ("computer", 25, "Advertises file sharing"),
    "_workstation._tcp": ("computer_linux", 30, "Advertises a Linux workstation"),
    "_ssh._tcp": ("computer_linux", 15, "Advertises SSH"),
    "_octoprint._tcp": ("sbc", 55, "Advertises OctoPrint (usually a Raspberry Pi)"),
    "_home-assistant._tcp": ("sbc", 40, "Home Assistant server"),
    "_nvstream._tcp": ("computer_windows", 30, "NVIDIA GameStream host"),
    "_xbox._tcp": ("console", 60, "Advertises Xbox"),
}

CAMERA_STRONG = (r"hikvision|dahua|ipcam|ip camera|network camera|netwave|webcam|\bdvr\b|\bnvr\b|xmeye|"
                 r"uc-httpd|hipcam|vstarcam|yoosee|reolink|amcrest|foscam|ezviz|imou|/doc/page/login|"
                 r"onvif|avtech|surveillance|camera|go2rtc|motioneye|blue iris|xiongmai")
CAMERA_WEAK = r"goahead|boa/|web service|mjpe?g|streamer|live ?view|thttpd"
TEXT_RULES = [
    # Must outweigh the Espressif vendor + ESP firmware clues combined.
    (r"esp32-?cam|esp-?eye|cameraweb", "camera", 120, "Runs ESP32-CAM camera firmware"),
    (CAMERA_STRONG, "camera", 60, "Web/UPnP info mentions camera software"),
    (CAMERA_WEAK, "camera", 25, "Web server type common on cheap cameras"),
    (r"esp32|esp8266|esphome|tasmota|wled|arduino|micropython|espressif|esp-idf|esp-async",
     "microcontroller", 55, "Web info mentions ESP/Arduino firmware"),
    (r"printer|laserjet|officejet|deskjet|epson|brother|canon|\bcups\b", "printer", 45, "Web info mentions a printer"),
    (r"synology|diskstation|qnap|truenas|openmediavault|unraid", "nas", 55, "Web info mentions NAS software"),
    (r"roku|samsung.*tv|tizen|webos|lg tv|bravia|fire ?tv|android ?tv|vizio|chromecast|mediarenderer",
     "tv", 45, "Describes itself as a TV / media renderer"),
    (r"sonos|bose|denon|heos|yamaha|amazon echo", "speaker", 50, "Describes itself as a speaker"),
    (r"internetgatewaydevice|openwrt|luci|dd-wrt|routeros|mikrotik|unifi|ubnt|airos|router",
     "network", 35, "Describes itself as a router / access point"),
    (r"philips hue|hue bridge|tuya|shelly|sonoff|smartthings|homebridge|node-red|zigbee",
     "iot", 45, "Describes itself as a smart-home device"),
    (r"home assistant|octoprint|pi-hole|raspberry", "sbc", 40, "Runs Raspberry-Pi-style server software"),
    (r"microsoft-windows|windows", "computer_windows", 30, "Describes itself as Windows"),
    (r"xbox|playstation", "console", 50, "Describes itself as a game console"),
    (r"pineapple|hak5|bettercap|evilginx|gophish|wifiphisher|\bbeef\b", "attack_tool", 85,
     "Web info matches a hacking / phishing tool"),
]

# Generic types get folded into the best matching specific one.
_FOLD = [
    ("apple", ["phone_apple", "computer_mac"]),
    ("phone", ["phone_apple", "phone_android"]),
    ("computer", ["computer_windows", "computer_mac", "computer_linux"]),
]


class _Scorer:
    def __init__(self) -> None:
        self.scores: dict[str, int] = defaultdict(int)
        self.reasons: dict[str, list[str]] = defaultdict(list)

    def add(self, dtype: str, weight: int, reason: str) -> None:
        self.scores[dtype] += weight
        if reason not in self.reasons[dtype]:
            self.reasons[dtype].append(reason)


def _match_rules(scorer: _Scorer, text: str, rules) -> None:
    if not text:
        return
    low = text.lower()
    for pattern, dtype, weight, reason in rules:
        if re.search(pattern, low):
            scorer.add(dtype, weight, reason)


def _device_text(d: Device) -> str:
    parts = []
    for b in d.banners.values():
        if b.get("kind") in ("http", "rtsp"):
            parts += [b.get("server", ""), b.get("title", ""), b.get("realm", ""), b.get("location", "")]
    parts += d.ssdp_servers
    parts += list(d.upnp.values())
    parts += d.wsd_types
    parts += list(d.mdns_txt.values())
    return " | ".join(p for p in parts if p)


def classify(d: Device) -> None:
    s = _Scorer()

    if d.is_self:
        own = "computer_windows" if IS_WINDOWS else "computer_mac" if IS_MAC else "computer_linux"
        s.add(own, 200, "This is the computer running Noxis")
    if d.is_gateway:
        s.add("router", 150, "Default gateway of this network")

    if d.vendor:
        _match_rules(s, d.vendor, VENDOR_RULES)
    if d.randomized_mac:
        s.add("phone", 25, "Uses a private (randomized) MAC address, typical of phones/tablets")

    for name in [*d.hostnames, d.netbios_name or "", d.upnp.get("friendlyName", "")]:
        _match_rules(s, name, NAME_RULES)
    if d.netbios_name:
        s.add("computer_windows", 30, f"Answers Windows network naming as '{d.netbios_name}'")

    for port in d.open_ports:
        if port in PORT_RULES:
            s.add(*PORT_RULES[port])

    for svc in d.mdns_services:
        if svc in MDNS_RULES:
            s.add(*MDNS_RULES[svc])
    model_txt = (d.mdns_txt.get("model") or d.mdns_txt.get("md") or d.mdns_txt.get("am") or "").lower()
    if model_txt.startswith(("iphone", "ipad")):
        s.add("phone_apple", 60, f"Reports model {model_txt}")
    elif model_txt.startswith(("macbook", "imac", "mac")):
        s.add("computer_mac", 60, f"Reports model {model_txt}")
    if d.mdns_txt.get("platform", "").lower().startswith("esp") or d.mdns_txt.get("board"):
        s.add("microcontroller", 60, "Reports an ESP board/platform over mDNS")

    _match_rules(s, _device_text(d), TEXT_RULES)

    for b in d.banners.values():
        if b.get("kind") == "rtsp":
            s.add("camera", 70, "Answers as an RTSP video server")
        banner = b.get("banner", "").lower()
        if "raspbian" in banner:
            s.add("sbc", 50, "SSH banner says Raspbian")
        elif "dropbear" in banner:
            s.add("iot", 10, "Embedded SSH server (dropbear)")
        elif "openssh_for_windows" in banner:
            s.add("computer_windows", 40, "Windows OpenSSH server")
        elif re.search(r"ubuntu|debian|fedora|arch", banner):
            s.add("computer_linux", 25, "SSH banner names a Linux distro")

    if d.onvif is not None:
        s.add("camera", 100, "Replied to ONVIF camera discovery")
    if any("Computer" in t for t in d.wsd_types):
        s.add("computer_windows", 45, "Announces itself as a Windows computer (WSD)")
    if any("PrintDevice" in t or "ScanDevice" in t for t in d.wsd_types):
        s.add("printer", 55, "Announces itself as a printer (WSD)")

    if d.ttl is not None and not d.is_self:
        if 65 <= d.ttl <= 128:
            s.add("computer_windows", 15, f"Ping TTL {d.ttl} (Windows default)")
        elif d.ttl > 128:
            s.add("network", 10, f"Ping TTL {d.ttl} (network gear / embedded)")

    for generic, specifics in _FOLD:
        if s.scores.get(generic):
            best = max(specifics, key=lambda t: s.scores.get(t, 0))
            if s.scores.get(best, 0) > 0:
                s.scores[best] += s.scores.pop(generic)
                s.reasons[best] += [r for r in s.reasons.pop(generic, []) if r not in s.reasons[best]]

    scores = {t: v for t, v in s.scores.items() if v > 0}
    d.type_scores = dict(sorted(scores.items(), key=lambda kv: -kv[1]))
    if not scores or max(scores.values()) < 15:
        d.device_type, d.confidence, d.evidence = "unknown", "low", []
    else:
        best = max(scores, key=scores.get)
        top = scores[best]
        d.device_type = best
        d.confidence = "high" if top >= 70 else "medium" if top >= 40 else "low"
        d.evidence = s.reasons[best][:6]
    d.type_label = TYPE_LABELS[d.device_type]
    d.model = _model(d)
    # A phone sharing its connection is the "router" of that network.
    if d.is_gateway:
        if d.type_scores.get("phone_apple", 0) >= 40:
            d.type_label, d.model = "Router: iPhone Personal Hotspot", d.model or "iPhone / iPad"
        elif d.type_scores.get("phone_android", 0) >= 40:
            d.type_label = "Router: Android hotspot"


def _model(d: Device) -> str | None:
    if d.onvif:
        hw = d.onvif.get("hardware") or d.onvif.get("name")
        if hw:
            return hw[:60]
    upnp = " ".join(x for x in (d.upnp.get("manufacturer"), d.upnp.get("modelName")) if x)
    if upnp:
        return upnp[:60]
    for key in ("md", "model", "am", "ty", "board", "product"):
        if d.mdns_txt.get(key):
            return d.mdns_txt[key][:60]
    return None
