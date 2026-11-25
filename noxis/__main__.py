"""Command-line interface: `python -m noxis <command>`."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import webbrowser
from datetime import datetime

from . import __version__, mitm, report, risk, upnp, wifi
from .models import Finding
from .oui import OuiDB, update_from_ieee
from .probes import MAX_DEEP_CONNECTIONS
from .scanner import DeepOnce, ScanError, merge_rounds, run_scan
from .store import Store, data_dir


def _log(msg: str) -> None:
    print(f"  {msg}", file=sys.stderr, flush=True)


def _assess(result, store: Store, extra=()) -> None:
    prev_gw = store.annotate(result)
    for d in result.devices:
        risk.assess_device(d, result.baseline_exists)
    risk.assess_network(result, prev_gw)
    check, net_findings, per_device = upnp.assess(result.upnp, result.devices, result.network.gateway_ip)
    if check is not None:
        result.checks = [c for c in result.checks if c.name != check.name] + [check]
        result.findings += net_findings
        for d in result.devices:
            d.findings += per_device.get(d.ip, [])
    if result.wifi_scanned:
        net = result.network
        result.findings += wifi.assess_nearby(
            result.nearby, net.ssid, net.bssid, store.known_bssids(net.network_id))
    # Trusted DNS servers and devices (a Pi-hole) were passed into the checks.
    result.findings += result.check_findings
    result.findings += extra
    store.record(result)


def _deep(args) -> DeepOnce | None:
    """--deep alone = every device; --deep 192.168.1.70 ... = just those.
    One tracker per run, so each device is deep-scanned once: in the first
    round, or in the round it first shows up."""
    value = getattr(args, "deep", None)
    if value is None:
        return None
    return DeepOnce(value or None, getattr(args, "deep_connections", None) or MAX_DEEP_CONNECTIONS)


def _connections(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' isn't a number") from None
    if not 1 <= n <= MAX_DEEP_CONNECTIONS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_DEEP_CONNECTIONS}")
    return n


def _deep_log(msg: str) -> None:
    """Monitor and sweep rounds are quiet, except to say why one is taking minutes."""
    if msg.startswith(("Deep scan:", "  deep scan:")):
        _log(f"[{datetime.now():%H:%M:%S}] {msg}")


def _context(store: Store):
    return lambda net: store.dns_context(net.network_id)


def _scan(args, store: Store, quiet: bool = False, deep: DeepOnce | None = None):
    oui = OuiDB(store.root)
    result = run_scan(oui, target=args.target, quick=args.quick,
                      log=_deep_log if quiet else _log, with_wifi=not args.no_wifi,
                      with_checks=not args.no_checks, context=_context(store),
                      deep=deep or _deep(args))
    _assess(result, store)
    return result


def _write_html(store: Store, result, prefix: str):
    reports = store.root / "reports"
    reports.mkdir(exist_ok=True)
    path = reports / f"{prefix}-{datetime.now():%Y%m%d-%H%M%S}.html"
    path.write_text(report.render_html(result), encoding="utf-8")
    return path


def cmd_scan(args) -> int:
    store = Store()
    result = _scan(args, store)
    path = None if args.no_html else _write_html(store, result, "noxis")
    report.print_report(result, str(path) if path else None)
    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2)
    if path and args.open:
        webbrowser.open(path.as_uri())
    return 0


def cmd_check(args) -> int:
    """Only the connection-integrity checks: fast, no device scan."""
    from .netinfo import get_network_info

    net = get_network_info()
    _log(f"Checking the connection on {net.label} (DNS: {', '.join(net.dns) or 'unknown'})...")
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        integrity = pool.submit(mitm.run_checks, net.dns, net.gateway_ip,
                                *Store().dns_context(net.network_id))
        forwards = pool.submit(upnp.read_port_forwards, net.local_ip, net.gateway_ip)
        checks, findings = integrity.result()
        check, net_findings, per_device = upnp.assess(forwards.result(), None, net.gateway_ip)
    checks.append(check)
    findings += net_findings + [f for fs in per_device.values() for f in fs]
    report.print_checks(checks, findings, header=f"Connection integrity: {net.label}")
    return 1 if any(f.severity == "high" for f in findings) else 0


def cmd_sweep(args) -> int:
    if args.rounds < 1 or args.wait < 0:
        print("--rounds must be at least 1 and --wait can't be negative.", file=sys.stderr)
        return 2
    store = Store()
    oui = OuiDB(store.root)
    results = []
    stop = threading.Event()
    hits: list[Finding] = []
    hp = None
    if args.honeypot or args.lure:
        hp = _start_honeypot(args, store, Alerter(store, args.beep, args.notify), stop, collect=hits)
    started = time.monotonic()
    minutes = round((args.rounds * 75 + (args.rounds - 1) * args.wait) / 60)
    _log(f"Sweeping: {args.rounds} rounds, {args.wait}s apart (about {max(minutes, 1)} min). "
         "Cameras that sleep or upload in bursts get more chances to show up.")
    stopped_early = False
    deep = _deep(args)  # one tracker for the whole sweep
    try:
        for i in range(1, args.rounds + 1):
            _log(f"Round {i}/{args.rounds}...")
            r = run_scan(oui, target=args.target, quick=args.quick, with_wifi=not args.no_wifi,
                         with_checks=not args.no_checks, context=_context(store),
                         deep=deep, log=_deep_log)
            results.append(r)
            _log(f"  {len(r.devices)} devices on the network"
                 + (f", {len(r.nearby)} nearby Wi-Fi access points" if r.wifi_scanned else ""))
            if i < args.rounds:
                time.sleep(args.wait)
    except KeyboardInterrupt:
        # Stopping early shouldn't throw away the evidence gathered so far.
        stopped_early = True
        stop.set()
        if not results:
            _log("Stopped before the first round finished, so there's no report to save."
                 + (" Honeypot alerts are in alerts.log." if hits else ""))
            return 130
        _log(f"Stopped after {len(results)} of {args.rounds} rounds. Saving the report so far...")
    result = merge_rounds(results)
    extra = list(hits)
    if stopped_early:
        extra.append(Finding(
            "info", "Sweep stopped early",
            f"Only {len(results)} of {args.rounds} rounds ran, so devices that were asleep may "
            "be missing. Run a full sweep if you can."))
    if hp is not None:
        stop.set()
        ran = round((time.monotonic() - started) / 60, 1)
        if hp.listening and not hits:
            extra.append(Finding(
                "info", "Honeypot: nobody probed the decoys",
                f"Decoy services on ports {', '.join(map(str, hp.listening))} ran for {ran} min "
                "with no visitors. Not proof nobody is snooping (a careful attacker may only "
                "listen), but no one scanned this computer while you were here."))
        elif not hp.listening:
            extra.append(Finding("info", "Honeypot didn't start",
                                 "No decoy port could be opened, so scanners weren't watched."))
    _assess(result, store, extra)
    path = _write_html(store, result, "sweep")
    report.print_report(result, str(path), checklist=True)
    if args.open:
        webbrowser.open(path.as_uri())
    return 0


def _notify(title: str, body: str) -> None:
    """Best-effort Windows toast notification."""
    import os
    if os.name != "nt":
        return
    from .util import run

    def q(s: str) -> str:
        return s.replace("'", "''")

    ps = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null;"
        "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
        f"$x=$t.GetElementsByTagName('text');$x.Item(0).AppendChild($t.CreateTextNode('{q(title)}'))>$null;"
        f"$x.Item(1).AppendChild($t.CreateTextNode('{q(body)}'))>$null;"
        "$id='{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe';"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($t))"
    )
    run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=15)


class Alerter:
    """One place for alerts: terminal, alerts.log, beep, desktop notification.
    Thread-safe, because the honeypot raises alerts from its own threads."""

    def __init__(self, store: Store, beep: bool = False, notify: bool = False):
        self.store, self.beep, self.notify = store, beep, notify
        self.log_path = store.root / "alerts.log"
        self.term = report.Term()
        self.lock = threading.Lock()

    def emit(self, text: str, severity: str = "high", detail: str = "", where: str = "") -> None:
        stamp = f"{datetime.now():%Y-%m-%d %H:%M:%S}"
        t = self.term
        with self.lock:
            t.out(t.c(severity, f"  ALERT [{stamp[11:]}] {text}") + ("\a" if self.beep else ""))
            if detail:
                t.out(t.c("dim", f"        {detail}"))
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(f"{stamp} {where} {text}\n")
        if self.notify:
            _notify("Noxis alert", text)


def _start_honeypot(args, store: Store, alerter: Alerter, stop: threading.Event,
                    collect: list | None = None):
    from .discovery import read_arp_table
    from .honeypot import Honeypot
    from .netinfo import get_network_info

    net = get_network_info()
    oui = OuiDB(store.root)
    known = store.network(net.network_id)["known"]

    def describe(ip: str) -> tuple[str, bool]:
        if not ip:
            return "an unknown device (Windows can't see who)", False
        if ip.startswith("127.") or ip == net.local_ip:
            return f"{ip} (this computer)", True
        mac = read_arp_table().get(ip)
        if not mac:
            return ip, False
        info = known.get(mac)
        vendor = oui.lookup(mac)
        label = (info or {}).get("name") or vendor or ("private MAC" if mac and int(mac[:2], 16) & 2 else "")
        return f"{ip} ({label + ', ' if label else ''}{'trusted' if info else 'untrusted'} {mac})", bool(info)

    def on_alert(a):
        who, trusted = describe(a.src_ip)
        severity, detail = a.severity, a.detail
        if trusted:
            # Your own machine running nmap or Noxis still deserves a mention.
            severity = "medium"
            detail += (" It came from this computer itself, so probably a test."
                       if "this computer" in who else
                       " The source is one of your trusted devices: ignore if it was you.")
        alerter.emit(f"Honeypot: {a.title} from {who}", severity, detail, where=net.label)
        if collect is not None:
            stamp = f"{datetime.now():%H:%M:%S}"
            collect.append(Finding(severity, f"Honeypot: {a.title} from {who}", f"[{stamp}] {detail}"))

    ports = [int(p) for p in args.ports.split(",")] if getattr(args, "ports", None) else None
    hp = Honeypot(net.local_ip, net.local_mac, on_alert, log_path=store.root / "honeypot.log",
                  ports=ports, bind=getattr(args, "bind", None) or "0.0.0.0",
                  lure=getattr(args, "lure", False))
    hp.start(stop)
    t = alerter.term
    t.out(t.c("bold", "Honeypot is up") + t.c("dim", f" on {net.local_ip}"))
    t.out(f"  Decoy ports: {', '.join(map(str, hp.listening)) or 'none'}")
    if getattr(args, "lure", False):
        from .honeypot import LURE_PORTS
        if any(p in hp.listening for p in LURE_PORTS):
            t.out(t.c("medium", "  Lure is on: this computer now answers on port 80, so it shows up "
                                "in scans while Noxis runs. It goes back to invisible when you stop."))
    for port, why in sorted(hp.skipped.items()):
        t.out(t.c("dim", f"  Skipped {port}: {why}"))
    if hp.sniffing:
        t.out("  Stealth-scan and network-sweep detection: on")
    elif hp.counting:
        t.out("  Stealth-scan detection: on (Windows can't tell who is scanning; "
              "network-sweep detection needs the Pi)")
    else:
        t.out(f"  Stealth-scan and network-sweep detection: off ({hp.sniff_note})")
    if os.name == "nt":
        t.out(t.c("medium", "  Windows Firewall: if it asks about Python, allow it, or other "
                            "devices can't reach the decoys. On a 'Public' network profile, "
                            "Windows blocks them unless you allow Public too."))
    return hp


def cmd_honeypot(args) -> int:
    store = Store()
    alerter = Alerter(store, args.beep, args.notify)
    stop = threading.Event()
    _start_honeypot(args, store, alerter, stop)
    alerter.term.out(alerter.term.c("dim", f"Waiting for visitors (Ctrl+C to stop). Logs: "
                                           f"{store.root / 'honeypot.log'}"))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        alerter.term.out("\nStopped.")
    return 0


def cmd_monitor(args) -> int:
    store = Store()
    alerter = Alerter(store, args.beep, args.notify)
    t = alerter.term
    stop = threading.Event()
    seen_macs: set[str] | None = None
    seen_alerts: set[str] = set()
    t.out(t.c("bold", f"Noxis monitor: scanning every {args.interval}s (Ctrl+C to stop)"))
    t.out(t.c("dim", f"Alerts are logged to {alerter.log_path}"))
    deep = _deep(args)
    if deep:
        t.out(t.c("dim", "Deep scan is on: every device gets a full port check in the first round, "
                         "then each new device when it joins."))
    if args.honeypot or args.lure:
        _start_honeypot(args, store, alerter, stop)
    try:
        while True:
            try:
                result = _scan(args, store, quiet=True, deep=deep)
            except ScanError as e:
                t.out(t.c("medium", f"[{datetime.now():%H:%M:%S}] scan skipped: {e}"))
                time.sleep(args.interval)
                continue
            alerts: list[str] = []
            macs = {d.mac for d in result.devices if d.mac}
            if seen_macs is not None:
                for d in result.devices:
                    if d.mac and d.mac not in seen_macs:
                        alerts.append(f"New device joined: {d.ip} {d.type_label}"
                                      + (f" ({d.vendor})" if d.vendor else ""))
            seen_macs = (seen_macs or set()) | macs
            for d in result.devices:
                for f in d.findings:
                    key = f"{d.mac or d.ip}|{f.title}"
                    if f.severity == "high" and key not in seen_alerts:
                        seen_alerts.add(key)
                        alerts.append(f"{d.ip} {d.type_label}: {f.title}")
            for f in result.findings:
                if f.severity == "high" and f.title not in seen_alerts:
                    seen_alerts.add(f.title)
                    alerts.append(f"Network: {f.title}")
            for ap in result.nearby:
                for f in ap.findings:
                    key = f"{ap.bssid}|{f.title}"
                    if f.severity == "high" and key not in seen_alerts:
                        seen_alerts.add(key)
                        alerts.append(f"Nearby Wi-Fi '{ap.ssid or '(hidden)'}': {f.title}")
            c = result.counts()
            with alerter.lock:
                t.out(t.c("dim", f"[{datetime.now():%H:%M:%S}] {len(result.devices)} devices, "
                                 f"{c['high']} high, {c['medium']} medium"))
            for a in alerts:
                alerter.emit(a, where=result.network.label)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        stop.set()
        t.out("\nStopped.")
    return 0


def cmd_trust(args) -> int:
    if not args.devices and not args.all:
        print("Give one or more IPs/MACs/names, or --all.", file=sys.stderr)
        return 2
    trusted = Store().trust(args.devices, args.name, args.all)
    if not trusted:
        print("No matching devices in the last scan.", file=sys.stderr)
        return 1
    print("Trusted:")
    for line in trusted:
        print(f"  {line}")
    return 0


def cmd_forget(args) -> int:
    removed = Store().forget(args.devices)
    print("Removed:" if removed else "Nothing matched.")
    for line in removed:
        print(f"  {line}")
    return 0


def cmd_known(args) -> int:
    store = Store()
    if not store.data:
        print("No networks recorded yet. Run `noxis scan`.")
    for net_id, net in store.data.items():
        print(f"{net_id}  ({len(net['known'])} trusted, {len(net['seen'])} seen)")
        for mac, info in net["known"].items():
            print(f"  {mac}  {info.get('ip', ''):<15} {info.get('name', '')}")
    return 0


def cmd_update_oui(args) -> int:
    print("Downloading the IEEE manufacturer registry...")
    count = update_from_ieee(data_dir())
    print(f"Saved {count:,} manufacturer prefixes to {data_dir() / 'oui.tsv'}")
    return 0


CONNECTIONS_HELP = (f"with --deep: how many ports to try at once per device (1-{MAX_DEEP_CONNECTIONS}, "
                    f"default {MAX_DEEP_CONNECTIONS}). Lower is gentler on small devices but slower: "
                    "about 4 min per device at 200, 8 at 100, 16 at 50")
DEEP_HELP = ("check all 65535 ports, to find services on unusual ports. Give IPs to deep-scan just "
             "those devices. Takes a few minutes per device that has a firewall")
LURE_HELP = ("also run a fake web login on port 80 (turns on the honeypot). This makes this computer "
             "visible to casual scans so scanners walk into the decoys; it's invisible again once "
             "Noxis stops")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="noxis", description="Local network security scanner.")
    p.add_argument("--version", action="version", version=f"noxis {__version__}")
    sub = p.add_subparsers(dest="command")

    def scan_opts(sp):
        sp.add_argument("--target", help="network to scan, e.g. 192.168.1.0/24 (default: yours)")
        sp.add_argument("--quick", action="store_true", help="probe fewer ports (faster)")
        sp.add_argument("--no-wifi", action="store_true", help="skip the nearby Wi-Fi networks check")
        sp.add_argument("--no-checks", action="store_true",
                        help="skip the HTTPS / DNS / HTTP integrity checks (they need internet)")

    s = sub.add_parser("scan", help="scan the network once (default)")
    scan_opts(s)
    s.add_argument("--deep", nargs="*", metavar="IP", help=DEEP_HELP)
    s.add_argument("--deep-connections", type=_connections, metavar="N", help=CONNECTIONS_HELP)
    s.add_argument("--open", action="store_true", help="open the HTML report when done")
    s.add_argument("--no-html", action="store_true", help="don't write an HTML report")
    s.add_argument("--json", metavar="PATH", help="also write results as JSON")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("check", help="only check the connection for interception (HTTPS, DNS, HTTP)")
    c.set_defaults(func=cmd_check)

    sw = sub.add_parser("sweep", help="thorough check of an unfamiliar place (rental, hotel)")
    scan_opts(sw)
    sw.add_argument("--rounds", type=int, default=4, help="number of scans (default 4)")
    sw.add_argument("--deep", nargs="*", metavar="IP",
                    help="check all 65535 ports on every device in the first round, and on any device "
                         "that first shows up in a later round. Give IPs to limit it to those")
    sw.add_argument("--deep-connections", type=_connections, metavar="N", help=CONNECTIONS_HELP)
    sw.add_argument("--wait", type=int, default=30, help="seconds between rounds (default 30)")
    sw.add_argument("--open", action="store_true", help="open the HTML report when done")
    sw.add_argument("--honeypot", action="store_true",
                    help="run decoy services for the whole sweep; hits go in the report")
    sw.add_argument("--ports", help="honeypot decoy ports, comma-separated (default: built-in list)")
    sw.add_argument("--lure", action="store_true", help=LURE_HELP)
    sw.add_argument("--beep", action="store_true", help="beep on honeypot alerts")
    sw.add_argument("--notify", action="store_true", help="Windows desktop notification on honeypot alerts")
    sw.set_defaults(func=cmd_sweep)

    m = sub.add_parser("monitor", help="scan repeatedly and alert on new/risky devices")
    scan_opts(m)
    m.add_argument("--interval", type=int, default=300, help="seconds between scans (default 300)")
    m.add_argument("--deep", nargs="*", metavar="IP",
                   help="check all 65535 ports on every device in the first round, then on each new "
                        "device when it joins (a few minutes each). Give IPs to limit it to those")
    m.add_argument("--deep-connections", type=_connections, metavar="N", help=CONNECTIONS_HELP)
    m.add_argument("--beep", action="store_true", help="beep on alerts")
    m.add_argument("--notify", action="store_true", help="Windows desktop notification on alerts")
    m.add_argument("--honeypot", action="store_true", help="also run decoy services to catch scanners")
    m.add_argument("--ports", help="honeypot decoy ports, comma-separated (default: built-in list)")
    m.add_argument("--lure", action="store_true", help=LURE_HELP)
    m.set_defaults(func=cmd_monitor)

    h = sub.add_parser("honeypot", help="run decoy services that alert when anyone touches them")
    h.add_argument("--ports", help="decoy ports, comma-separated (default: built-in list)")
    h.add_argument("--lure", action="store_true", help=LURE_HELP)
    h.add_argument("--bind", help="address to listen on (default 0.0.0.0 = all; 127.0.0.1 to test locally)")
    h.add_argument("--beep", action="store_true", help="beep on alerts")
    h.add_argument("--notify", action="store_true", help="Windows desktop notification on alerts")
    h.set_defaults(func=cmd_honeypot)

    tr = sub.add_parser("trust", help="mark devices from the last scan as yours")
    tr.add_argument("devices", nargs="*", help="IP, MAC or name")
    tr.add_argument("--name", help="friendly name (when trusting one device)")
    tr.add_argument("--all", action="store_true", help="trust every device in the last scan")
    tr.set_defaults(func=cmd_trust)

    f = sub.add_parser("forget", help="remove devices from the trusted list")
    f.add_argument("devices", nargs="+", help="IP, MAC or name")
    f.set_defaults(func=cmd_forget)

    k = sub.add_parser("known", help="list trusted devices per network")
    k.set_defaults(func=cmd_known)

    u = sub.add_parser("update-oui", help="download the full IEEE manufacturer list")
    u.set_defaults(func=cmd_update_oui)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        args = parser.parse_args(["scan", *(argv if argv is not None else sys.argv[1:])])
    if getattr(args, "deep_connections", None) and getattr(args, "deep", None) is None:
        parser.error("--deep-connections only applies together with --deep")
    try:
        return args.func(args)
    except (ScanError, RuntimeError) as e:
        print(f"noxis: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
