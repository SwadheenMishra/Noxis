"""Persistent state: trusted devices per network, device history, last scan."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

from .models import ScanResult
from .services import snapshot
from .util import normalize_mac


def data_dir() -> Path:
    """~/.noxis on every OS. (Not %LOCALAPPDATA%: Windows gives packaged apps,
    such as terminals or editors installed from the Store, a private redirected
    copy of AppData, so two programs could each see a different Noxis folder.)"""
    home = os.environ.get("NOXIS_HOME") or os.environ.get("WARDEN_HOME")  # old name still works
    if home:
        path = Path(home)
    else:
        path = Path.home() / ".noxis"
        if not path.exists():
            # One-time copy from where earlier versions (named Warden) kept their data:
            # trusted devices, DNS servers, logs and reports carry over. The old
            # folder is left in place as a backup.
            legacies = [Path.home() / ".warden"]
            if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
                legacies.append(Path(os.environ["LOCALAPPDATA"]) / "Warden")  # oldest location
            for legacy in legacies:
                if legacy.is_dir():
                    import shutil
                    shutil.copytree(legacy, path)
                    break
    path.mkdir(parents=True, exist_ok=True)
    return path


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _write_json(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


class Store:
    def __init__(self, root: Path | None = None):
        self.root = root or data_dir()
        self.path = self.root / "networks.json"
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.data = {}

    def save(self) -> None:
        _write_json(self.path, self.data)

    def network(self, net_id: str) -> dict:
        return self.data.setdefault(net_id, {"known": {}, "seen": {}, "gateway_mac": None})

    def dns_context(self, net_id: str) -> tuple[dict[str, str], list[str]]:
        """(trusted devices by IP, trusted DNS servers) for the DNS check."""
        net = self.network(net_id)
        known_lan = {info["ip"]: info.get("name") or info.get("type") or "trusted device"
                     for info in net["known"].values() if info.get("ip")}
        return known_lan, list(net.get("dns", []))

    # -- scan integration ---------------------------------------------------

    def annotate(self, result: ScanResult) -> str | None:
        """Mark trusted/new devices. Returns the previously recorded gateway MAC."""
        net = self.network(result.network.network_id)
        result.baseline_exists = bool(net["known"])
        for d in result.devices:
            if not d.mac:
                continue
            known = net["known"].get(d.mac)
            if known:
                d.trusted = True
                d.known_name = known.get("name") or None
                d.trusted_profile = known.get("profile")
            d.first_seen_now = bool(net["seen"]) and d.mac not in net["seen"]
        return net.get("gateway_mac")

    def known_bssids(self, net_id: str) -> list[str]:
        return list(self.network(net_id).get("bssids", []))

    def record(self, result: ScanResult) -> None:
        net = self.network(result.network.network_id)
        if result.network.gateway_mac:
            net["gateway_mac"] = result.network.gateway_mac
        net["ssid"] = result.network.ssid
        net["cidr"] = result.network.cidr
        for d in result.devices:
            if not d.mac:
                continue
            entry = net["seen"].setdefault(d.mac, {"first_seen": result.started})
            entry.update(last_seen=result.started, last_ip=d.ip, type=d.device_type,
                         vendor=d.vendor, name=d.display_name())
        self.save()
        _write_json(self.root / "last_scan.json", result.to_dict())

    # -- trust management ---------------------------------------------------

    def last_scan(self) -> dict | None:
        try:
            return json.loads((self.root / "last_scan.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _trust_device(net: dict, dev: dict, label: str) -> dict:
        old = (net["known"].get(dev["mac"]) or {}).get("profile") or {}
        services = snapshot(dev.get("services", []))
        for port, saved in (old.get("services") or {}).items():
            if port in services and saved.get("name"):
                services[port]["name"] = saved["name"]  # keep nicknames across re-trusts
        entry = net["known"][dev["mac"]] = {
            "name": label, "trusted_at": _now(), "ip": dev["ip"], "type": dev["type_label"],
            # What the device looked like when trusted. A later scan that
            # finds this MAC looking different suggests a copied MAC.
            "profile": {
                "type": dev.get("device_type"),
                "ports": dev.get("open_ports", []),
                "vendor": dev.get("vendor"),
                "services": services,
            },
        }
        return entry

    def trust(self, identifiers: list[str], name: str | None, trust_all: bool) -> list[str]:
        scan = self.last_scan()
        if not scan:
            raise RuntimeError("No scan found yet. Run `noxis scan` first.")
        net = self.network(scan["network"]["network_id"])
        # "192.168.1.70:8096" means one service; anything else means a device.
        service_ids = [i for i in identifiers if re.fullmatch(r"\d+\.\d+\.\d+\.\d+:\d+", i.strip())]
        device_ids = [i for i in identifiers if i not in service_ids]
        targets = []
        for dev in scan["devices"]:
            if not dev.get("mac") or dev.get("is_self"):
                continue
            if trust_all or any(_matches(dev, i) for i in device_ids):
                targets.append(dev)
        trusted = []
        device_name = name if not service_ids else None
        for dev in targets:
            label = device_name if (device_name and len(targets) == 1) else (dev.get("display_name") or "")
            if label == dev.get("type_label"):
                label = ""
            self._trust_device(net, dev, label)
            trusted.append(f"{dev['ip']:<15} {dev['mac']}  {label or dev['type_label']}")

        for ident in service_ids:
            ip, port = ident.strip().rsplit(":", 1)
            dev = next((d for d in scan["devices"] if d.get("ip") == ip and d.get("mac")), None)
            svc = next((s for s in (dev or {}).get("services", []) if str(s["port"]) == port), None)
            if dev is None or svc is None:
                raise RuntimeError(f"No service on {ident} in the last scan.")
            entry = net["known"].get(dev["mac"])
            if entry is None:
                entry = self._trust_device(net, dev, dev.get("display_name") or "")
                trusted.append(f"{dev['ip']:<15} {dev['mac']}  {dev['type_label']} (device trusted too)")
            profile = entry.setdefault("profile", {})
            saved = profile.setdefault("services", {})
            nickname = name or (saved.get(port) or {}).get("name", "")
            saved[port] = {"id": svc["fingerprint"], "label": svc["name"], "name": nickname}
            profile["ports"] = sorted(set(profile.get("ports") or []) | {int(port)})
            trusted.append(f"{ident:<21} {nickname or svc['name']}")

        # Trust this network's access points too (for evil-twin detection).
        ssid = scan["network"].get("ssid")
        bssids = set(net.get("bssids", []))
        if scan["network"].get("bssid"):
            bssids.add(scan["network"]["bssid"])
        if trust_all and ssid:
            bssids |= {ap["bssid"] for ap in scan.get("nearby", []) if ap["ssid"] == ssid}
        if bssids - set(net.get("bssids", [])):
            new = sorted(bssids - set(net.get("bssids", [])))
            trusted += [f"access point {b} for '{ssid}'" for b in new]
        net["bssids"] = sorted(bssids)

        # And the DNS servers this network hands out, so a change can be spotted.
        if trust_all:
            dns = [ip for ip in scan["network"].get("dns", []) if ip and ip != "0.0.0.0"]
            new = [ip for ip in dns if ip not in net.get("dns", [])]
            if dns:
                net["dns"] = dns
            trusted += [f"DNS server {ip}" for ip in new]
        self.save()
        return trusted

    def forget(self, identifiers: list[str]) -> list[str]:
        removed = []
        for net in self.data.values():
            for mac, info in list(net["known"].items()):
                dev = {"mac": mac, "ip": info.get("ip"), "display_name": info.get("name")}
                if any(_matches(dev, i) for i in identifiers):
                    del net["known"][mac]
                    removed.append(f"{mac}  {info.get('name')}")
        self.save()
        return removed


def _matches(dev: dict, ident: str) -> bool:
    ident = ident.strip()
    if ident == dev.get("ip"):
        return True
    mac = normalize_mac(ident)
    if mac and mac == dev.get("mac"):
        return True
    name = (dev.get("display_name") or "").lower()
    return bool(name) and ident.lower() == name
