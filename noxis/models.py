"""Data classes shared across the scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    severity: str  # high | medium | low | info
    title: str
    detail: str = ""


@dataclass
class Device:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    randomized_mac: bool = False
    hostnames: list[str] = field(default_factory=list)
    netbios_name: str | None = None
    netbios_group: str | None = None
    ttl: int | None = None
    ping: bool = False
    open_ports: list[int] = field(default_factory=list)
    # port -> {"kind": "http"|"rtsp"|"ssh"|"banner", ...}
    banners: dict[int, dict[str, str]] = field(default_factory=dict)
    services: list = field(default_factory=list)  # services.Service, one per open port
    mdns_services: list[str] = field(default_factory=list)
    mdns_txt: dict[str, str] = field(default_factory=dict)
    ssdp_servers: list[str] = field(default_factory=list)
    upnp: dict[str, str] = field(default_factory=dict)
    onvif: dict[str, str] | None = None
    wsd_types: list[str] = field(default_factory=list)
    is_self: bool = False
    is_gateway: bool = False
    # classification
    device_type: str = "unknown"
    type_label: str = "Unknown device"
    confidence: str = "low"
    evidence: list[str] = field(default_factory=list)
    type_scores: dict[str, int] = field(default_factory=dict)
    model: str | None = None
    # baseline
    known_name: str | None = None
    trusted: bool = False
    trusted_profile: dict | None = None  # fingerprint saved when it was trusted
    first_seen_now: bool = False
    seen_rounds: list[int] = field(default_factory=list)  # sweep rounds it answered in
    findings: list[Finding] = field(default_factory=list)

    def add_hostname(self, name: str | None) -> None:
        if not name:
            return
        name = name.strip().rstrip(".")
        if not name or name.lower() in (h.lower() for h in self.hostnames):
            return
        self.hostnames.append(name)

    @property
    def risk(self) -> str:
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    @property
    def risk_rank(self) -> int:
        return SEVERITY_ORDER.get(self.risk, -1)

    def display_name(self) -> str:
        if self.known_name:
            return self.known_name
        if self.is_self:
            return "This computer"
        for source in (self.upnp.get("friendlyName"), self.netbios_name):
            if source:
                return source
        if self.hostnames:
            return self.hostnames[0]
        return self.model or ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["banners"] = {str(k): v for k, v in self.banners.items()}
        d["risk"] = self.risk
        d["display_name"] = self.display_name()
        return d


@dataclass
class NetworkInfo:
    local_ip: str
    prefix: int
    cidr: str
    gateway_ip: str | None = None
    gateway_mac: str | None = None
    local_mac: str | None = None
    interface: str | None = None
    ssid: str | None = None
    bssid: str | None = None  # access point we're connected through
    dns: list[str] = field(default_factory=list)  # DNS servers this computer uses

    @property
    def network_id(self) -> str:
        if self.ssid:
            return f"wifi:{self.ssid}"
        return f"lan:{self.gateway_ip or self.cidr}"

    @property
    def label(self) -> str:
        return self.ssid or self.interface or self.cidr


@dataclass
class ScanResult:
    network: NetworkInfo
    devices: list[Device]
    started: str
    duration: float = 0.0
    findings: list[Finding] = field(default_factory=list)  # network-level
    baseline_exists: bool = False
    oui_sources: list[str] = field(default_factory=list)
    nearby: list = field(default_factory=list)  # wifi.AccessPoint
    wifi_scanned: bool = False
    wifi_stale: bool = False  # couldn't ask for a fresh Wi-Fi scan (Linux permissions)
    rounds: int = 1  # >1 for a sweep
    round_times: list[str] = field(default_factory=list)
    checks: list = field(default_factory=list)  # mitm.Check results
    check_findings: list[Finding] = field(default_factory=list)
    upnp: object = None  # upnp.UpnpInfo: router port forwards

    def counts(self) -> dict[str, int]:
        c = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for d in self.devices:
            if d.risk in c:
                c[d.risk] += 1
        return c

    def flagged_aps(self) -> list:
        return [ap for ap in self.nearby if any(f.severity != "info" for f in ap.findings)]

    def to_dict(self) -> dict:
        return {
            "network": {**asdict(self.network), "network_id": self.network.network_id},
            "started": self.started,
            "duration": round(self.duration, 1),
            "baseline_exists": self.baseline_exists,
            "oui_sources": self.oui_sources,
            "findings": [asdict(f) for f in self.findings],
            "devices": [d.to_dict() for d in self.devices],
            "nearby": [ap.to_dict() for ap in self.nearby],
            "rounds": self.rounds,
            "round_times": self.round_times,
            "checks": [asdict(c) for c in self.checks],
            "upnp": self.upnp.to_dict() if self.upnp is not None else None,
        }
