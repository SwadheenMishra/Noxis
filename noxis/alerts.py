"""What counts as an alert: presets, per-rule mutes, and repeat suppression.

Every possible alert belongs to a *rule*. A preset gives each rule a level:

    off    ignored
    log    written to alerts.log only
    alert  terminal, alerts.log, --beep and --notify
    push   like alert, and also sent as a push notification (`noxis push`)

A rule is either a group (`device-high`, `honeypot`, ...) or one specific
finding by its name (`dns-server-changed`), which overrides its group.
Presets are picked per network: networks with trusted devices use `home`,
others `travel`, unless you assign one. Mutes silence one rule, optionally
only from one source, on one network or in a time window; muted alerts are
still logged.

Settings live in alerts.json, monitor memory in monitor_state.json (both in
the Noxis data folder).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .store import read_json, write_json
from .util import normalize_mac

LEVELS = ["off", "log", "alert", "push"]
# Before push notifications were built, the top level was called phone.
LEVEL_ALIASES = {"phone": "push"}

# rule -> what it covers (shown by `noxis alerts rules`)
RULES: dict[str, str] = {
    "new-device": "A device joins that this network hasn't had before",
    "device-high": "High-risk finding on a device (cameras, copied MACs, dangerous services...)",
    "device-medium": "Medium finding on a device (new service on a trusted device...)",
    "device-low": "Low finding on a device",
    "network-high": "High-risk finding about the network (gateway MAC changed, HTTPS intercepted...)",
    "network-medium": "Medium finding about the network (DNS server changed...)",
    "network-low": "Low finding about the network",
    "wifi-high": "High-risk nearby Wi-Fi (camera hotspots, open evil twins)",
    "wifi-medium": "Medium nearby Wi-Fi (possible evil twins, microcontroller hotspots)",
    "wifi-low": "Low nearby Wi-Fi (strong hidden networks)",
    "honeypot": "Someone touched or scanned the decoys, or stealth-scanned this machine",
    "network-sweep": "A device mapped every address on the network (Linux as root)",
    "lure-visit": "A single visit to the fake web login (--lure)",
}

BUILTIN: dict[str, dict[str, str]] = {
    # The network you live on: everything new is worth knowing about.
    "home": {
        "new-device": "alert",
        "device-high": "alert", "device-medium": "log", "device-low": "off",
        "network-high": "alert", "network-medium": "log", "network-low": "off",
        "wifi-high": "alert", "wifi-medium": "log", "wifi-low": "off",
        "honeypot": "push", "network-sweep": "push", "lure-visit": "alert",
    },
    # Hotels, cafes, other people's networks: strangers' devices are normal
    # here, so only what threatens you (cameras, evil twins, interception,
    # someone probing this machine) alerts.
    "travel": {
        "new-device": "off",
        "device-high": "alert", "device-medium": "log", "device-low": "off",
        "network-high": "alert", "network-medium": "log", "network-low": "off",
        "wifi-high": "alert", "wifi-medium": "log", "wifi-low": "off",
        "honeypot": "push", "network-sweep": "alert", "lure-visit": "log",
    },
}

REARM_ROUNDS = 3  # a problem must be gone this many rounds before it can alert again
FORGET_AFTER = timedelta(days=7)  # drop memory of problems not seen for this long


def slug(title: str) -> str:
    """'DNS server changed' -> 'dns-server-changed'."""
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")


# ------------------------------------------------------------------ alerts


@dataclass
class Alert:
    rule: str  # group rule, e.g. device-high
    title: str  # finding title (its slug is the specific rule)
    text: str  # one line for the terminal and log
    key: str = ""  # identity for repeat suppression
    detail: str = ""
    severity: str = "high"
    src_ip: str | None = None
    src_mac: str | None = None
    device: str | None = None  # MAC the finding belongs to (repeat suppression)
    scope: str = "network"  # device | network | wifi | event
    reminder: bool = False

    @property
    def name(self) -> str:
        return slug(self.title)


def from_result(result) -> tuple[list[Alert], list[Alert]]:
    """(new-device candidates, finding alerts) from one scan round."""
    new, found = [], []
    for d in result.devices:
        name = f"{d.ip} {d.type_label}" + (f" ({d.vendor})" if d.vendor else "")
        if d.mac:
            new.append(Alert("new-device", "New device joined", f"New device joined: {name}",
                             key=f"new|{d.mac}", src_ip=d.ip, src_mac=d.mac, device=d.mac,
                             scope="device", severity="medium"))
        for f in d.findings:
            if f.severity == "info":
                continue
            found.append(Alert(f"device-{f.severity}", f.title, f"{d.ip} {d.type_label}: {f.title}",
                               key=f"{d.mac or d.ip}|{f.title}", detail=f.detail, severity=f.severity,
                               src_ip=d.ip, src_mac=d.mac, device=d.mac, scope="device"))
    for f in result.findings:
        if f.severity == "info" or f.title.startswith("Honeypot:"):
            continue
        found.append(Alert(f"network-{f.severity}", f.title, f"Network: {f.title}", key=f.title,
                           detail=f.detail, severity=f.severity, scope="network"))
    for ap in result.nearby:
        for f in ap.findings:
            if f.severity == "info":
                continue
            found.append(Alert(f"wifi-{f.severity}", f.title,
                               f"Nearby Wi-Fi '{ap.ssid or '(hidden)'}': {f.title}",
                               key=f"{ap.bssid}|{f.title}", detail=f.detail, severity=f.severity,
                               src_mac=ap.bssid, scope="wifi"))
    return new, found


def honeypot_rule(title: str) -> str:
    if title == "Network sweep detected":
        return "network-sweep"
    if title.startswith("Visit to the lure"):
        return "lure-visit"
    return "honeypot"


# ------------------------------------------------------------------ mutes


def parse_window(text: str) -> tuple[str, str]:
    """'02:00-03:30' -> ('02:00', '03:30'). Raises ValueError."""
    m = re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*", text or "")
    if not m or int(m[1]) > 23 or int(m[3]) > 23 or int(m[2]) > 59 or int(m[4]) > 59:
        raise ValueError(f"'{text}' isn't a time window like 02:00-03:30")
    return f"{int(m[1]):02d}:{m[2]}", f"{int(m[3]):02d}:{m[4]}"


def in_window(window: list[str] | tuple[str, str], now: datetime) -> bool:
    start, end = window
    t = f"{now:%H:%M}"
    if start <= end:
        return start <= t < end
    return t >= start or t < end  # crosses midnight, e.g. 23:00-01:00


def mute_matches(mute: dict, alert: Alert, net_id: str, now: datetime) -> bool:
    if mute.get("rule") not in (alert.rule, alert.name):
        return False
    if mute.get("network") and mute["network"] != net_id:
        return False
    src = mute.get("source")
    if src:
        mac = normalize_mac(src)
        if mac:
            if mac != alert.src_mac:
                return False
        elif src != alert.src_ip:
            return False
    if mute.get("window") and not in_window(mute["window"], now):
        return False
    return True


def describe_mute(m: dict) -> str:
    parts = [m["rule"]]
    if m.get("source"):
        parts.append(f"from {m['source']}")
    if m.get("network"):
        parts.append(f"on {m['network']}")
    if m.get("window"):
        parts.append(f"{m['window'][0]}-{m['window'][1]}")
    text = " ".join(parts)
    return text + (f"  ({m['note']})" if m.get("note") else "")


# ------------------------------------------------------------------ config


class Config:
    """alerts.json: user presets, which preset each network uses, mutes."""

    def __init__(self, root: Path):
        self.path = root / "alerts.json"
        data = read_json(self.path, {})
        if not isinstance(data, dict):
            data = {}
        self.presets: dict[str, dict[str, str]] = data.get("presets", {})
        self.networks: dict[str, str] = data.get("networks", {})
        self.defaults: dict[str, str] = {"trusted": "home", "untrusted": "travel",
                                         **data.get("defaults", {})}
        self.mutes: list[dict] = data.get("mutes", [])

    def save(self) -> None:
        write_json(self.path, {"presets": self.presets, "networks": self.networks,
                               "defaults": self.defaults, "mutes": self.mutes})

    # -- presets

    def names(self) -> list[str]:
        return list(BUILTIN) + [n for n in self.presets if n not in BUILTIN]

    def exists(self, name: str) -> bool:
        return name in BUILTIN or name in self.presets

    def preset(self, name: str) -> dict[str, str]:
        if name in BUILTIN:
            return dict(BUILTIN[name])
        if name in self.presets:
            # A preset made from an older Noxis may lack newer rules, or say "phone".
            merged = {**BUILTIN["home"], **self.presets[name]}
            return {k: LEVEL_ALIASES.get(v, v) for k, v in merged.items()}
        raise KeyError(name)

    def preset_for(self, net_id: str, trusted_network: bool) -> str:
        name = self.networks.get(net_id) or self.defaults["trusted" if trusted_network else "untrusted"]
        return name if self.exists(name) else ("home" if trusted_network else "travel")

    def level(self, preset: dict[str, str], alert: Alert) -> str:
        return preset.get(alert.name) or preset.get(alert.rule, "off")

    def create(self, name: str, base: str) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", name):
            raise ValueError("Preset names use lowercase letters, digits, - and _ (up to 32).")
        if self.exists(name):
            raise ValueError(f"There's already a preset called '{name}'.")
        if not self.exists(base):
            raise ValueError(f"No preset called '{base}'.")
        self.presets[name] = self.preset(base)

    def set_level(self, name: str, rule: str, level: str) -> str:
        if name in BUILTIN:
            raise ValueError(f"'{name}' is built in and can't be changed. Make your own copy: "
                             f"noxis alerts new my-{name} --from {name}")
        if name not in self.presets:
            raise ValueError(f"No preset called '{name}'.")
        level = LEVEL_ALIASES.get(level, level)
        if level not in LEVELS:
            raise ValueError(f"Level must be one of: {', '.join(LEVELS)}.")
        rule = rule if rule in RULES else slug(rule)
        if not rule:
            raise ValueError("Give a rule name (see `noxis alerts rules`) or a finding's name.")
        self.presets[name][rule] = level
        return rule

    def delete(self, name: str) -> None:
        if name in BUILTIN:
            raise ValueError(f"'{name}' is built in and can't be deleted.")
        if self.presets.pop(name, None) is None:
            raise ValueError(f"No preset called '{name}'.")
        self.networks = {k: v for k, v in self.networks.items() if v != name}
        for kind in ("trusted", "untrusted"):
            if self.defaults.get(kind) == name:
                self.defaults[kind] = "home" if kind == "trusted" else "travel"

    # -- decisions

    def decide(self, preset: dict[str, str], alert: Alert, net_id: str,
               now: datetime | None = None) -> tuple[str, dict | None]:
        """(level, mute that silenced it or None)."""
        level = self.level(preset, alert)
        if level == "off":
            return level, None
        now = now or datetime.now()
        for m in self.mutes:
            if mute_matches(m, alert, net_id, now):
                return level, m
        return level, None


# ------------------------------------------------------------- monitor state


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds")


@dataclass
class MonitorState:
    """What the monitor remembers between rounds and across restarts, per
    network: devices it has seen, and problems that are still going on."""

    path: Path
    data: dict = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path) -> "MonitorState":
        data = read_json(root / "monitor_state.json", {})
        return cls(root / "monitor_state.json", data if isinstance(data, dict) else {})

    def save(self) -> None:
        write_json(self.path, self.data)

    def _net(self, net_id: str) -> dict | None:
        return self.data.setdefault("networks", {}).get(net_id)

    def new_devices(self, net_id: str, result, candidates: list[Alert]) -> list[Alert]:
        """Devices this monitor hasn't seen on this network before. The first
        time a network is monitored, its scan history decides (so a device that
        joined since the last scan still counts); with no history at all, the
        first round is the baseline."""
        net = self._net(net_id)
        now = _iso(datetime.now())
        if net is None:
            first_seen_now = {d.mac for d in result.devices if d.mac and d.first_seen_now}
            fresh = [a for a in candidates if a.src_mac in first_seen_now]
            net = self.data["networks"][net_id] = {"devices": {}, "active": {}}
        else:
            fresh = [a for a in candidates if a.src_mac not in net["devices"]]
        for a in candidates:
            net["devices"].setdefault(a.src_mac, now)
        return fresh

    def update(self, net_id: str, alerts: list[Alert], present_macs: set[str],
               wifi_scanned: bool, remind_hours: float | None = None,
               now: datetime | None = None) -> list[Alert]:
        """Which of this round's problems to raise: new ones, and reminders for
        ones still going on after `remind_hours`. A problem that disappears
        re-arms after REARM_ROUNDS rounds without it. A device that's offline
        (or a Wi-Fi scan that didn't run) doesn't count as the problem going
        away, so a camera that sleeps between rounds doesn't alert every time
        it wakes up."""
        now = now or datetime.now()
        net = self.data.setdefault("networks", {}).setdefault(net_id, {"devices": {}, "active": {}})
        active: dict = net.setdefault("active", {})
        fire = []
        current = {a.key: a for a in alerts}
        seen: set[str] = set()
        for key, a in current.items():
            key, entry = self._find(active, key, a)
            seen.add(key)
            if entry is None:
                active[key] = {"since": _iso(now), "alerted": _iso(now), "last_seen": _iso(now),
                               "missing": 0, "scope": a.scope, "device": a.device, "ip": a.src_ip}
                fire.append(a)
                continue
            entry.update(last_seen=_iso(now), missing=0)
            if a.src_ip:
                entry["ip"] = a.src_ip
            if remind_hours and now - datetime.fromisoformat(entry["alerted"]) >= timedelta(hours=remind_hours):
                entry["alerted"] = _iso(now)
                a.reminder = True
                fire.append(a)
        for key in list(active):
            if key in seen:
                continue
            entry = active[key]
            if now - datetime.fromisoformat(entry["last_seen"]) > FORGET_AFTER:
                del active[key]
                continue
            if entry.get("scope") == "device" and entry.get("device") not in present_macs:
                continue  # device offline: can't tell whether the problem is gone
            if entry.get("scope") == "wifi" and not wifi_scanned:
                continue
            entry["missing"] = entry.get("missing", 0) + 1
            if entry["missing"] >= REARM_ROUNDS:
                del active[key]
        return fire

    @staticmethod
    def _find(active: dict, key: str, a: Alert) -> tuple[str, dict | None]:
        """The remembered problem this alert continues. A device's MAC isn't
        always resolved (it can answer late, or not answer ARP in a round), so
        the same problem may arrive keyed by IP one round and by MAC the next."""
        if key in active:
            return key, active[key]
        if a.scope != "device" or not a.src_ip:
            return key, None
        for k, e in active.items():
            if (e.get("scope") == "device" and e.get("ip") == a.src_ip and k.endswith("|" + a.title)
                    and (e.get("device") is None or a.device is None or e["device"] == a.device)):
                if a.device and e.get("device") is None:
                    e["device"] = a.device  # now we know its MAC: keep it under that
                    del active[k]
                    active[key] = e
                    return key, e
                return k, e
        return key, None
