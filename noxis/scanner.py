"""Run a full scan: discover -> probe -> fingerprint."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from datetime import datetime
from typing import Callable

from . import discovery, fingerprint, mitm, probes, protocols, services, upnp, wifi
from .models import Device, NetworkInfo, ScanResult
from .netinfo import get_network_info
from .oui import OuiDB
from .util import IS_WINDOWS, is_randomized_mac

MAX_HOSTS = 1024


class ScanError(Exception):
    pass


class DeepOnce:
    """Deep-scan (all 65535 ports) each device once per run: every device in
    the first round, then each device the first time it shows up. Sleepy
    devices that were missed early still get checked, without paying minutes
    per device every round. Ports a deep scan found are re-checked in every
    later round so they don't seem to vanish."""

    def __init__(self, only: list[str] | None = None,
                 connections: int = probes.MAX_DEEP_CONNECTIONS):
        self.only = set(only) if only else None  # --deep 192.168.1.70 ...: just these
        self.connections = connections  # simultaneous connections per device (--deep-connections)
        # One record per deep-scanned device: {"ip", "mac", "extra": ports only a deep scan found}.
        # A device's MAC is often unknown when its deep scan starts (it shows up in the
        # ARP table later), so records match by MAC when both sides have one, else by IP.
        self.records: list[dict] = []

    def find(self, d: Device) -> dict | None:
        for r in self.records:
            if d.mac and r["mac"]:
                if d.mac == r["mac"]:
                    return r
            elif d.ip == r["ip"]:
                return r
        return None

    def pick(self, devices: list[Device]) -> list[Device]:
        todo = [d for d in devices if self.find(d) is None
                and (self.only is None or d.ip in self.only)]
        self.records += [{"ip": d.ip, "mac": d.mac, "extra": set()} for d in todo]
        return todo

    def remember(self, d: Device, ports: set[int]) -> None:
        r = self.find(d)
        if r is not None:
            r["extra"] |= ports

    def extra_for(self, d: Device) -> set[int]:
        r = self.find(d)
        return r["extra"] if r else set()

    def learn(self, devices) -> None:
        """Fill in MACs the scan learned after the deep scan started."""
        for r in self.records:
            if not r["mac"]:
                d = next((d for d in devices if d.ip == r["ip"] and d.mac), None)
                if d:
                    r["mac"] = d.mac


def resolve_target(net: NetworkInfo, target: str | None) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(target or net.cidr, strict=False)
    except ValueError as e:
        raise ScanError(f"Not a valid network: {target}") from e
    if not isinstance(network, ipaddress.IPv4Network):
        raise ScanError("Only IPv4 networks are supported.")
    if not (network.is_private or network.is_link_local):
        raise ScanError(f"{network} is not a private network. Noxis only scans local networks.")
    if network.num_addresses > MAX_HOSTS + 2:
        if target:
            raise ScanError(f"{network} is too big ({network.num_addresses} addresses, max {MAX_HOSTS}).")
        # Huge DHCP subnet (e.g. /16 hotel Wi-Fi): scan the /24 around us.
        network = ipaddress.ip_network(f"{net.local_ip}/24", strict=False)
    return network


async def _scan(net: NetworkInfo, network: ipaddress.IPv4Network, oui: OuiDB,
                quick: bool, log: Callable[[str], None], with_wifi: bool = True,
                with_checks: bool = True, context=None, deep=None):
    local = net.local_ip
    hosts = [str(h) for h in network.hosts() if str(h) != local]

    log(f"Sweeping {len(hosts)} addresses on {network}...")
    ping_sem = asyncio.Semaphore(96)
    tcp_sem = asyncio.Semaphore(256)

    async def tcp_alive(ip):
        for port in (80, 443, 22, 62078):
            if await discovery.tcp_state(ip, port, 0.8, tcp_sem):
                return True
        return False

    # Everything that doesn't depend on knowing the hosts runs at once.
    ping_task = asyncio.gather(*(discovery.ping(ip, 800, ping_sem) for ip in hosts))
    arp_task = discovery.sendarp_sweep(hosts)
    tcp_task = (asyncio.gather(*(tcp_alive(ip) for ip in hosts))
                if not IS_WINDOWS else asyncio.sleep(0, result=[False] * len(hosts)))
    mdns_task = asyncio.to_thread(protocols.mdns_discover, local)
    ssdp_task = asyncio.to_thread(protocols.ssdp_discover, local)
    wsd_task = asyncio.to_thread(protocols.wsd_discover, local)
    wifi_task = (asyncio.to_thread(wifi.scan_nearby, oui) if with_wifi
                 else asyncio.sleep(0, result=[]))
    known_lan, trusted_dns = context(net) if context else ({}, [])
    checks_task = (asyncio.to_thread(mitm.run_checks, net.dns, net.gateway_ip, known_lan, trusted_dns)
                   if with_checks
                   else asyncio.sleep(0, result=([], [])))
    upnp_task = asyncio.to_thread(upnp.read_port_forwards, local, net.gateway_ip)
    ttls, sendarp, tcp_up, mdns, ssdp, wsd, nearby, checks, forwards = await asyncio.gather(
        ping_task, arp_task, tcp_task, mdns_task, ssdp_task, wsd_task, wifi_task, checks_task,
        upnp_task,
    )

    arp = discovery.read_arp_table()
    arp.update(sendarp)
    in_net = lambda ip: ipaddress.ip_address(ip) in network  # noqa: E731

    alive: set[str] = {ip for ip in arp if in_net(ip)}
    alive |= {ip for ip, ttl in zip(hosts, ttls) if ttl is not None}
    alive |= {ip for ip, up in zip(hosts, tcp_up) if up}
    alive |= {ip for ip in (*mdns, *ssdp, *wsd) if in_net(ip)}
    alive.discard(local)
    if net.gateway_ip and in_net(net.gateway_ip):
        alive.add(net.gateway_ip)

    devices: dict[str, Device] = {}
    devices[local] = Device(ip=local, mac=net.local_mac, is_self=True, ping=True)
    for ip in alive:
        devices[ip] = Device(ip=ip, mac=arp.get(ip))
    ttl_by_ip = dict(zip(hosts, ttls))
    for ip, d in devices.items():
        if ttl_by_ip.get(ip) is not None:
            d.ping, d.ttl = True, ttl_by_ip[ip]
        if ip == net.gateway_ip:
            d.is_gateway = True
            net.gateway_mac = d.mac

    targets = sorted(alive, key=ipaddress.ip_address)
    log(f"Found {len(targets)} other device(s). Fingerprinting...")
    port_list = probes.QUICK_PORTS if quick else list(probes.PORTS)
    open_ports, nb, rdns, upnp_desc = await asyncio.gather(
        probes.scan_ports(targets, port_list),
        asyncio.to_thread(discovery.netbios_names, targets, local),
        discovery.reverse_dns(targets),
        asyncio.to_thread(protocols.fetch_upnp_descriptions, ssdp, network),
    )
    if deep:
        tracker = deep if isinstance(deep, DeepOnce) else DeepOnce(None if deep is True else deep)
        normal = set(port_list)
        new = tracker.pick([devices[ip] for ip in targets])
        new_ips = {d.ip for d in new}
        # Devices deep-scanned in an earlier round: re-check what that found.
        recheck = {ip: tracker.extra_for(devices[ip]) for ip in targets
                   if ip not in new_ips and tracker.extra_for(devices[ip])}
        if recheck:
            again = await probes.scan_ports(list(recheck), sorted(set().union(*recheck.values())))
            for ip, ports in again.items():
                open_ports[ip] = sorted(set(open_ports.get(ip, [])) | (set(ports) & recheck[ip]))
        if new:
            log(f"Deep scan: all 65535 ports on {len(new)} device(s), {tracker.connections} "
                "connections at a time. This takes a few minutes...")
            found = await probes.deep_scan([d.ip for d in new], per_host=tracker.connections, log=log)
            for d in new:
                ports = set(found.get(d.ip, []))
                tracker.remember(d, ports - normal)
                open_ports[d.ip] = sorted(set(open_ports.get(d.ip, [])) | ports)
    banners = await probes.grab_banners(open_ports)

    # Sleepy devices (phones in power-save) often only show up in the ARP
    # table after the port scan has talked to them, so look again.
    late_arp = discovery.read_arp_table()
    for ip, d in devices.items():
        if not d.mac and ip in late_arp:
            d.mac = late_arp[ip]
            if d.is_gateway:
                net.gateway_mac = d.mac
    if deep:
        tracker.learn(devices.values())

    for ip, d in devices.items():
        if d.mac:
            d.randomized_mac = is_randomized_mac(d.mac)
            d.vendor = oui.lookup(d.mac)
        d.open_ports = open_ports.get(ip, [])
        d.banners = banners.get(ip, {})
        if ip in nb:
            d.netbios_name, d.netbios_group = nb[ip]
        d.add_hostname(rdns.get(ip))
        if ip in mdns:
            m = mdns[ip]
            d.mdns_services = sorted(m["services"])
            d.mdns_txt = m["txt"]
            for inst in sorted(m["instances"]):
                # Linux (Avahi) names workstations "host [aa:bb:cc:dd:ee:ff]".
                d.add_hostname(re.sub(r"\s*\[[0-9a-fA-F:]{17}\]$", "", inst))
            for host in sorted(m["hostnames"]):
                d.add_hostname(host)
            for key in ("fn", "friendly_name", "n"):
                d.add_hostname(m["txt"].get(key))
        if ip in ssdp:
            d.ssdp_servers = sorted(ssdp[ip]["servers"])
        if ip in upnp_desc:
            d.upnp = upnp_desc[ip]
        if ip in wsd:
            d.wsd_types = sorted(wsd[ip]["types"])
            d.onvif = wsd[ip]["onvif"]
        fingerprint.classify(d)
        d.services = services.identify_all(d)

    return (sorted(devices.values(), key=lambda d: ipaddress.ip_address(d.ip)), nearby, checks,
            forwards)


def run_scan(oui: OuiDB, target: str | None = None, quick: bool = False,
             log: Callable[[str], None] = lambda _: None, with_wifi: bool = True,
             with_checks: bool = True, context=None, deep=None) -> ScanResult:
    """`context(net) -> (trusted devices by IP, trusted DNS servers)` lets the
    connection checks know what you've already trusted on this network."""
    t0 = time.monotonic()
    started = datetime.now().isoformat(timespec="seconds")
    log("Reading network settings...")
    net = get_network_info()
    if net.local_ip.startswith("127."):
        raise ScanError("Not connected to a network.")
    network = resolve_target(net, target)
    if str(network) != net.cidr:
        net.cidr = str(network)
    if with_wifi and net.ssid:
        net.bssid = wifi.connected_bssid()
    devices, nearby, (checks, check_findings), forwards = asyncio.run(
        _scan(net, network, oui, quick, log, with_wifi, with_checks, context, deep))
    return ScanResult(
        network=net, devices=devices, started=started,
        duration=time.monotonic() - t0, oui_sources=oui.sources,
        nearby=nearby, wifi_scanned=with_wifi, round_times=[started],
        wifi_stale=with_wifi and not IS_WINDOWS and not wifi.rescan_allowed(),
        checks=checks, check_findings=check_findings, upnp=forwards,
    )


def _merge_device(into: Device, d: Device) -> None:
    into.mac = into.mac or d.mac
    into.ping = into.ping or d.ping
    into.ttl = into.ttl or d.ttl
    into.open_ports = sorted(set(into.open_ports) | set(d.open_ports))
    for port, info in d.banners.items():
        into.banners.setdefault(port, info)
    into.mdns_services = sorted(set(into.mdns_services) | set(d.mdns_services))
    for k, v in d.mdns_txt.items():
        into.mdns_txt.setdefault(k, v)
    for h in d.hostnames:
        into.add_hostname(h)
    into.netbios_name = into.netbios_name or d.netbios_name
    into.netbios_group = into.netbios_group or d.netbios_group
    into.ssdp_servers = sorted(set(into.ssdp_servers) | set(d.ssdp_servers))
    for k, v in d.upnp.items():
        into.upnp.setdefault(k, v)
    into.onvif = into.onvif or d.onvif
    into.wsd_types = sorted(set(into.wsd_types) | set(d.wsd_types))


def merge_rounds(results: list[ScanResult]) -> ScanResult:
    """Combine several scans into one: every device seen in any round, with
    everything learned about it across all rounds."""
    base = results[-1]
    devices: list[Device] = []
    for i, r in enumerate(results, start=1):
        for d in r.devices:
            # Same MAC = same device. Same IP only if one side has no MAC
            # (a sleepy device whose MAC we missed in one round).
            match = next((m for m in devices if d.mac and m.mac == d.mac), None)
            if match is None:
                match = next((m for m in devices if m.ip == d.ip
                              and (not m.mac or not d.mac)), None)
            if match is None:
                d.seen_rounds = [i]
                devices.append(d)
            else:
                _merge_device(match, d)
                if i not in match.seen_rounds:
                    match.seen_rounds.append(i)
    aps: dict[str, object] = {}
    for i, r in enumerate(results, start=1):
        for ap in r.nearby:
            if ap.bssid not in aps:
                ap.seen_rounds = [i]
                aps[ap.bssid] = ap
            else:
                prev = aps[ap.bssid]
                prev.signal = max(prev.signal or 0, ap.signal or 0)
                prev.seen_rounds.append(i)
    for d in devices:
        fingerprint.classify(d)
        d.services = services.identify_all(d)
    gw = next((d for d in devices if d.is_gateway and d.mac), None)
    if gw:
        base.network.gateway_mac = gw.mac
    # Keep the most alarming round's integrity results, and every distinct finding.
    worst = max(results, key=lambda r: sum(c.status in ("fail", "warn") for c in r.checks))
    check_findings, titles = [], set()
    for r in results:
        for f in r.check_findings:
            if f.title not in titles:
                titles.add(f.title)
                check_findings.append(f)
    # Port forwards: the last round that could read them, with every forward seen.
    forwards = next((r.upnp for r in reversed(results) if r.upnp and r.upnp.status == "ok"),
                    results[-1].upnp)
    if forwards is not None and forwards.status == "ok":
        seen = {(m.protocol, m.external_port) for m in forwards.mappings}
        for r in results:
            for m in (r.upnp.mappings if r.upnp else []):
                if (m.protocol, m.external_port) not in seen:
                    seen.add((m.protocol, m.external_port))
                    forwards.mappings.append(m)
    return ScanResult(
        upnp=forwards,
        checks=worst.checks,
        check_findings=check_findings,
        network=base.network,
        devices=sorted(devices, key=lambda d: ipaddress.ip_address(d.ip)),
        started=results[0].started,
        duration=sum(r.duration for r in results),
        oui_sources=base.oui_sources,
        nearby=sorted(aps.values(), key=lambda a: -(a.signal or 0)),
        wifi_scanned=any(r.wifi_scanned for r in results),
        wifi_stale=any(r.wifi_stale for r in results),
        rounds=len(results),
        round_times=[r.started for r in results],
    )
