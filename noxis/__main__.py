"""Command-line interface: `python -m noxis <command>`."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import webbrowser
from datetime import datetime

from . import __version__, alerts, mitm, push, report, risk, service, upnp, wifi
from .models import Finding
from .oui import OuiDB, update_from_ieee
from .probes import MAX_DEEP_CONNECTIONS
from .scanner import DeepOnce, ScanError, merge_rounds, run_scan
from .store import Store, data_dir, read_json, write_json
from .util import append_line, fix_owner


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


def _level(text: str) -> str:
    level = alerts.LEVEL_ALIASES.get(text, text)
    if level not in alerts.LEVELS:
        raise argparse.ArgumentTypeError(f"'{text}' isn't a level ({', '.join(alerts.LEVELS)})")
    return level


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
    if not reports.exists():
        reports.mkdir()
        fix_owner(reports)
    path = reports / f"{prefix}-{datetime.now():%Y%m%d-%H%M%S}.html"
    path.write_text(report.render_html(result), encoding="utf-8")
    fix_owner(path)
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
    hp = alerter = None
    if args.honeypot or args.lure:
        alerter = Alerter(store, args.beep, args.notify)
        hp = _start_honeypot(args, store, alerter, stop, collect=hits)
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
            if alerter is not None:
                alerter.close()
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
        alerter.close()  # push notifications still waiting go out now
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


def _linux_notify_cmd(title: str, body: str) -> list[str] | None:
    """notify-send for the desktop of whoever is logged in, or None if there's
    no way to show one (no notify-send, or no desktop session, e.g. a Pi used
    only over SSH).

    Under sudo, the notification must go to the invoking user's desktop
    session, not root's (which has none)."""
    import shutil
    exe = shutil.which("notify-send")
    if not exe:
        return None
    cmd = [exe, "--app-name=Noxis", "--urgency=critical", title, body]
    user, uid = os.environ.get("SUDO_USER"), os.environ.get("SUDO_UID")
    as_sudo = os.geteuid() == 0 and user and user != "root" and uid
    uid = uid if as_sudo else str(os.getuid())
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS") if not as_sudo else None
    if not bus:
        path = f"/run/user/{uid}/bus"
        if not os.path.exists(path):
            return None
        bus = f"unix:path={path}"
    cmd = ["env", f"DBUS_SESSION_BUS_ADDRESS={bus}", *cmd]
    if as_sudo:
        cmd = ["sudo", "-u", user, *cmd]
    return cmd


def notify_problem() -> str | None:
    """Why --notify can't work here, or None if it can."""
    if os.name == "nt":
        return None
    if sys.platform.startswith("linux"):
        import shutil
        if not shutil.which("notify-send"):
            return ("notify-send isn't installed (on Debian, Ubuntu or Raspberry Pi OS: "
                    "sudo apt install libnotify-bin)")
        if _linux_notify_cmd("", "") is None:
            return "there's no desktop session to show it on (e.g. a machine you only reach over SSH)"
        return None
    return "desktop notifications aren't supported on this system yet"


def _notify(title: str, body: str) -> None:
    """Best-effort desktop notification: a Windows toast, or notify-send on Linux."""
    from .util import run
    if sys.platform.startswith("linux"):
        cmd = _linux_notify_cmd(title, body)
        if cmd:
            run(cmd, timeout=10)
        return
    if os.name != "nt":
        return

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
    Thread-safe, because the honeypot raises alerts from its own threads.

    `send` applies the alert preset for the network and any mutes; `emit`
    shows an alert unconditionally."""

    def __init__(self, store: Store, beep: bool = False, notify: bool = False,
                 preset: str | None = None):
        self.store, self.beep, self.notify = store, beep, notify
        self.preset_override = preset
        self.log_path = store.root / "alerts.log"
        self.term = report.Term()
        self.lock = threading.Lock()
        self.push_cfg = push.PushConfig(store.root)
        self.pusher = push.Pusher(self.push_cfg.channels) if self.push_cfg.channels else None
        # Counted since the last summary (see _Heartbeat).
        self.stats = {"alerts": 0, "pushed": 0, "muted": 0, "rounds": 0}
        if notify and (why := notify_problem()):
            self.notify = False
            self.term.out(self.term.c("medium", f"--notify is off: {why}. Alerts still show here "
                                                f"and in {self.log_path}."))

    def push(self, msg: "push.Message") -> None:
        if self.pusher is not None:
            self.pusher.send(msg)

    def close(self) -> None:
        """Deliver push notifications still waiting before Noxis exits."""
        if self.pusher is not None:
            self.pusher.close()

    def preset_name(self, cfg: alerts.Config, net_id: str, trusted_network: bool) -> str:
        if self.preset_override and cfg.exists(self.preset_override):
            return self.preset_override
        return cfg.preset_for(net_id, trusted_network)

    def send(self, alert: alerts.Alert, net_id: str, trusted_network: bool, where: str) -> str:
        """Raise one alert as its preset and mutes say. Returns the level used,
        or 'muted'. Settings are re-read each time, so `noxis alerts` and
        `noxis mute` changes apply to a monitor that's already running."""
        cfg = alerts.Config(self.store.root)
        level, mute = cfg.decide(cfg.preset(self.preset_name(cfg, net_id, trusted_network)),
                                 alert, net_id)
        if level == "off":
            return level
        text = ("Still going on: " if alert.reminder else "") + alert.text
        rule = alert.rule if alert.name == alert.rule else f"{alert.rule} | {alert.name}"
        if mute is not None or level == "log":
            note = f"  (muted: {alerts.describe_mute(mute)})" if mute is not None else ""
            with self.lock:
                append_line(self.log_path, f"{datetime.now():%Y-%m-%d %H:%M:%S} {where} [{rule}] "
                                           f"{text}{note}")
                if mute is not None:
                    self.stats["muted"] += 1
            return "muted" if mute is not None else level
        self.emit(text, alert.severity, alert.detail, where, rule)
        with self.lock:
            self.stats["alerts"] += 1
        if level == "push" and self.pusher is not None:
            if alert.reminder:
                import dataclasses
                alert = dataclasses.replace(alert, text=text)
            self.pusher.send(push.alert_message(alert, where))
            with self.lock:
                self.stats["pushed"] += 1
        return level

    def emit(self, text: str, severity: str = "high", detail: str = "", where: str = "",
             rule: str = "") -> None:
        stamp = f"{datetime.now():%Y-%m-%d %H:%M:%S}"
        t = self.term
        with self.lock:
            t.out(f"  {report.alert_mark(t)} " + t.c(severity, f"ALERT [{stamp[11:]}] {text}")
                  + ("\a" if self.beep else ""))
            if detail:
                t.out(t.c("dim", f"        {detail}"))
            append_line(self.log_path, f"{stamp} {where} " + (f"[{rule}] " if rule else "") + text)
        if self.notify:
            _notify("Noxis alert", text)


class _LiveNetwork:
    """The honeypot's view of the network, kept current while it runs: this
    machine's address (DHCP can change it) and which devices are trusted
    (`noxis trust` can change that)."""

    REFRESH = 60  # seconds

    def __init__(self, store: Store):
        from .netinfo import get_network_info
        self.store = store
        self.net = get_network_info()
        self.oui = OuiDB(store.root)

    def refresh(self, hp=None) -> None:
        from .netinfo import get_network_info
        try:
            net = get_network_info()
        except Exception:
            return  # keep the last good view; the network may be down for a moment
        if not net.local_ip:
            return
        self.net = net
        if hp is not None:
            hp.set_local(net.local_ip, net.local_mac)

    def keep_fresh(self, hp, stop: threading.Event) -> None:
        while not stop.wait(self.REFRESH):
            self.refresh(hp)

    def describe(self, ip: str) -> tuple[str, bool, str | None]:
        """(how to name the source, whether it's trusted, its MAC)."""
        from .discovery import read_arp_table
        net = self.net
        if not ip:
            return "an unknown device (Windows can't see who)", False, None
        if ip.startswith("127.") or ip == net.local_ip:
            return f"{ip} (this computer)", True, net.local_mac
        mac = read_arp_table().get(ip)
        if not mac:
            return ip, False, None
        info = self.store.known(net.network_id).get(mac)
        vendor = self.oui.lookup(mac)
        label = (info or {}).get("name") or vendor or ("private MAC" if int(mac[:2], 16) & 2 else "")
        return (f"{ip} ({label + ', ' if label else ''}{'trusted' if info else 'untrusted'} {mac})",
                bool(info), mac)


def _start_honeypot(args, store: Store, alerter: Alerter, stop: threading.Event,
                    collect: list | None = None):
    from .honeypot import Honeypot

    live = _LiveNetwork(store)
    net = live.net
    alerter.network_label = net.label  # for the push summary

    def on_alert(a):
        net = live.net
        who, trusted, mac = live.describe(a.src_ip)
        severity, detail = a.severity, a.detail
        if trusted:
            # Your own machine running nmap or Noxis still deserves a mention.
            severity = "medium"
            detail += (" It came from this computer itself, so probably a test."
                       if "this computer" in who else
                       " The source is one of your trusted devices: ignore if it was you.")
        alert = alerts.Alert(alerts.honeypot_rule(a.title), a.title, f"Honeypot: {a.title} from {who}",
                             detail=detail, severity=severity, src_ip=a.src_ip or None, src_mac=mac,
                             scope="event")
        alerter.send(alert, net.network_id, bool(store.known(net.network_id)), net.label)
        if collect is not None:
            stamp = f"{datetime.now():%H:%M:%S}"
            collect.append(Finding(severity, f"Honeypot: {a.title} from {who}", f"[{stamp}] {detail}"))

    t = alerter.term
    ports = [int(p) for p in args.ports.split(",")] if getattr(args, "ports", None) else None
    hp = Honeypot(net.local_ip, net.local_mac, on_alert, log_path=store.root / "honeypot.log",
                  ports=ports, bind=getattr(args, "bind", None) or "0.0.0.0",
                  lure=getattr(args, "lure", False),
                  on_note=lambda msg: t.out(t.c("medium", f"  [{datetime.now():%H:%M:%S}] {msg}")))
    hp.start(stop)
    threading.Thread(target=live.keep_fresh, args=(hp, stop), daemon=True,
                     name="noxis-netwatch").start()
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
        t.out("  Stealth-scan and network-sweep detection: on"
              + ("" if hp.filtered else " (without a kernel filter: it may miss scans while "
                                        "this computer is busy)"))
    elif hp.counting:
        t.out("  Stealth-scan detection: on (Windows can't tell who is scanning; "
              "network-sweep detection needs Linux as root)")
    else:
        t.out(f"  Stealth-scan and network-sweep detection: off ({hp.sniff_note})")
    if os.name == "nt":
        t.out(t.c("medium", "  Windows Firewall: if it asks about Python, allow it, or other "
                            "devices can't reach the decoys. On a 'Public' network profile, "
                            "Windows blocks them unless you allow Public too."))
    return hp


def _stop_on_sigterm() -> None:
    """`systemctl stop` and `kill` send SIGTERM: stop as cleanly as Ctrl+C."""
    import signal

    def handler(signum, frame):
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, handler)
    except (ValueError, OSError, AttributeError):
        pass  # not the main thread (tests), or no SIGTERM here


def _log_error(store: Store, what: str) -> None:
    import traceback
    append_line(store.root / "errors.log",
                f"{datetime.now():%Y-%m-%d %H:%M:%S} {what}\n{traceback.format_exc()}")


class _Heartbeat:
    """Push messages about Noxis itself, for long-running commands: when it
    starts and stops, and a summary on a schedule. A summary that doesn't
    arrive when expected means the machine or Noxis is down."""

    CHECK = 30  # seconds between summary checks

    def __init__(self, alerter: Alerter, what: str, stop: threading.Event):
        self.alerter, self.what, self.stop = alerter, what, stop
        self.started = datetime.now()
        self.host = push.host_name()
        self.network = "the network"  # updated by the monitor each round
        self.devices: int | None = None
        self.state_path = alerter.store.root / "push_state.json"

    def describe(self) -> str:
        cfg = self.alerter.push_cfg
        if not cfg.channels:
            return "not set up (`noxis push add ntfy`)"
        names = ", ".join(push.describe_channel(c).split("  ")[0] for c in cfg.channels)
        return (f"{names}; start/stop messages {'on' if cfg.startstop else 'off'}, "
                f"summary {push.describe_summary(cfg.summary)}")

    @property
    def as_service(self) -> bool:
        return os.environ.get("NOXIS_SERVICE") == "1"

    def start(self) -> None:
        resumed = self.as_service and service.take_event(self.alerter.store.root) == "resumed"
        if self.alerter.pusher is None:
            return
        if self.alerter.push_cfg.startstop:
            if resumed:
                self.alerter.push(push.status_message(
                    "Noxis resumed", f"{self.what} on {self.host} is watching again.",
                    f"{self.what} on {self.host} resumed."))
            else:
                self.alerter.push(push.status_message(
                    "Noxis started", f"{self.what} started on {self.host}.",
                    f"{self.what} started on {self.host}."))
        if self.alerter.push_cfg.summary:
            threading.Thread(target=self._loop, daemon=True, name="noxis-summary").start()

    def finish(self, crash: str | None = None) -> None:
        """`crash`: the error that ended it, or None for a normal stop. A crash
        is sent with high priority: that's the stop worth noticing."""
        if self.alerter.pusher is not None and self.alerter.push_cfg.startstop:
            hours, rest = divmod(int((datetime.now() - self.started).total_seconds()), 3600)
            ran = f"after {hours}h {rest // 60}m"
            if crash:
                msg = push.status_message(
                    "Noxis crashed", f"{self.what} on {self.host} crashed ({crash}) {ran}. "
                    f"Details are in errors.log there.", f"{self.what} on {self.host} crashed.")
                msg.priority, msg.tags = 4, ["warning"]
            elif self.as_service and service.read_state(self.alerter.store.root).get("event") == "removed":
                msg = push.status_message(
                    "Noxis service removed", f"{self.what} on {self.host} was uninstalled {ran}, "
                    "so it won't start again on its own.", f"{self.what} on {self.host} was uninstalled.")
            elif self.as_service and service.read_state(self.alerter.store.root).get("event") == "paused":
                msg = push.status_message(
                    "Noxis paused", f"{self.what} on {self.host} was paused {ran}. It stays paused, "
                    "even after a restart, until `noxis service resume`.",
                    f"{self.what} on {self.host} was paused.")
            else:
                msg = push.status_message(
                    "Noxis stopped", f"{self.what} on {self.host} was stopped (Ctrl+C, or the system "
                    f"shut it down) {ran}.", f"{self.what} on {self.host} was stopped.")
            self.alerter.push(msg)
        self.alerter.close()

    def _last(self) -> datetime | None:
        try:
            return datetime.fromisoformat(read_json(self.state_path, {}).get("last_summary", ""))
        except (ValueError, TypeError, AttributeError):
            return None

    def _loop(self) -> None:
        while not self.stop.wait(self.CHECK):
            spec = push.PushConfig(self.alerter.store.root).summary  # `noxis push summary` applies live
            if push.summary_due(spec, self._last(), self.started, datetime.now()):
                self.send_summary()

    def send_summary(self) -> None:
        a = self.alerter
        with a.lock:
            s = dict(a.stats)
            a.stats.update(alerts=0, pushed=0, muted=0, rounds=0)
        last = self._last()
        # Counts restart with each run, so "since the last summary" only when
        # that summary came from this run; otherwise "so far".
        this_run = last is not None and last >= self.started.replace(microsecond=0)  # saved to the second
        since = f"since {last:%a %H:%M}" if this_run else "so far"
        lines = [f"Still watching {self.network} from {self.host}.",
                 f"{since[0].upper() + since[1:]}: " + (f"{s['rounds']} scans, " if s["rounds"] else "")
                 + f"{s['alerts']} alerts ({s['pushed']} pushed, {s['muted']} muted)."]
        if self.devices is not None:
            lines.append(f"{self.devices} devices on the network now.")
        lines.append(f"Running since {self.started:%a %d %b %H:%M}.")
        if a.pusher is not None and (a.pusher.pending() or a.pusher.dropped):
            lines.append(f"{a.pusher.pending()} notifications waiting to be sent, "
                         f"{a.pusher.dropped} dropped (server unreachable).")
        a.push(push.status_message(
            "Noxis summary", "\n".join(lines),
            f"Still watching from {self.host}. {s['alerts']} alerts {since}. "
            f"Running since {self.started:%a %d %b %H:%M}."))
        write_json(self.state_path, {"last_summary": datetime.now().isoformat(timespec="seconds")})


def cmd_honeypot(args) -> int:
    store = Store()
    alerter = Alerter(store, args.beep, args.notify)
    stop = threading.Event()
    _stop_on_sigterm()
    beat = _Heartbeat(alerter, "Honeypot", stop)
    crash = None
    try:
        _start_honeypot(args, store, alerter, stop)
        beat.network = getattr(alerter, "network_label", beat.network)
        alerter.term.out(f"  Push notifications: {beat.describe()}")
        alerter.term.out(alerter.term.c("dim", f"Waiting for visitors (Ctrl+C to stop). Logs: "
                                               f"{store.root / 'honeypot.log'}"))
        beat.start()
        while True:
            if service.STOP.wait(1):  # `noxis service pause` on Windows
                raise KeyboardInterrupt
    except KeyboardInterrupt:
        alerter.term.out("\nStopped.")
    except BaseException as e:
        crash = type(e).__name__
        raise
    finally:
        stop.set()
        beat.finish(crash)
    return 0


def _linux_hints(wifi_check: bool = True) -> list[str]:
    """Things on this Linux machine that make Noxis miss things, with the fix."""
    if not service.IS_LINUX:
        return []
    hints = []
    if wifi_check and not wifi.rescan_allowed():
        hints.append(f"Nearby Wi-Fi: {wifi.STALE_NOTE}")
    if hint := wifi.power_save_hint():
        hints.append(hint)
    return hints


def _monitor_round(result, state: alerts.MonitorState, alerter: Alerter,
                   remind: float | None, shown: dict, beat: "_Heartbeat | None" = None) -> None:
    """Turn one scan into alerts. `shown` remembers which preset was announced
    for which network, so moving to another network says what changed."""
    net = result.network
    net_id, trusted_network = net.network_id, result.baseline_exists
    cfg = alerts.Config(alerter.store.root)
    name = alerter.preset_name(cfg, net_id, trusted_network)
    t = alerter.term
    if shown.get("preset") != (net_id, name):
        shown["preset"] = (net_id, name)
        with alerter.lock:
            t.out(t.c("dim", f"On {net.label}: alert preset '{name}' "
                             f"({'a network you trust devices on' if trusted_network else 'no trusted devices here'})"))
    new, found = alerts.from_result(result)
    fresh = state.new_devices(net_id, result, new)
    present = {d.mac for d in result.devices if d.mac}
    fire = state.update(net_id, found, present, result.wifi_scanned, remind)
    c = result.counts()
    with alerter.lock:
        t.out(t.c("dim", f"[{datetime.now():%H:%M:%S}] {len(result.devices)} devices, "
                         f"{c['high']} high, {c['medium']} medium"))
    for a in fresh + fire:
        alerter.send(a, net_id, trusted_network, net.label)
    state.save()
    with alerter.lock:
        alerter.stats["rounds"] += 1
    if beat is not None:
        beat.network, beat.devices = net.label, len(result.devices)


def cmd_monitor(args) -> int:
    store = Store()
    preset = getattr(args, "preset", None)
    if preset and not alerts.Config(store.root).exists(preset):
        raise RuntimeError(f"No alert preset called '{preset}'. See `noxis alerts`.")
    remind = getattr(args, "remind", None)
    if remind is not None and remind <= 0:
        raise RuntimeError("--remind must be a number of hours above 0.")
    alerter = Alerter(store, args.beep, args.notify, preset=preset)
    state = alerts.MonitorState.load(store.root)
    t = alerter.term
    stop = threading.Event()
    _stop_on_sigterm()
    t.out(t.c("bold", f"Noxis monitor: scanning every {args.interval}s (Ctrl+C to stop)"))
    t.out(t.c("dim", f"Alerts are logged to {alerter.log_path}"))
    deep = _deep(args)
    if deep:
        t.out(t.c("dim", "Deep scan is on: every device gets a full port check in the first round, "
                         "then each new device when it joins."))
    shown: dict = {}
    honeypot = args.honeypot or args.lure
    minutes = args.interval / 60
    every = f"{minutes:g} min" if minutes >= 1 else f"{args.interval}s"
    beat = _Heartbeat(alerter, f"Monitor (scans every {every}{', honeypot on' if honeypot else ''})",
                      stop)
    t.out(t.c("dim", f"Push notifications: {beat.describe()}"))
    for hint in _linux_hints(wifi_check=not args.no_wifi):
        t.out(t.c("medium", hint))
    crash = None
    try:
        if honeypot:
            _start_honeypot(args, store, alerter, stop)
        beat.start()
        while True:
            try:
                result = _scan(args, store, quiet=True, deep=deep)
                _monitor_round(result, state, alerter, remind, shown, beat)
            except ScanError as e:
                t.out(t.c("medium", f"[{datetime.now():%H:%M:%S}] scan skipped: {e}"))
            except Exception as e:  # a 24/7 monitor must outlive one bad round
                _log_error(store, "monitor round failed")
                t.out(t.c("medium", f"[{datetime.now():%H:%M:%S}] round failed ({type(e).__name__}: "
                                    f"{e}); trying again next round. Details: "
                                    f"{store.root / 'errors.log'}"))
            if service.STOP.wait(args.interval):  # `noxis service pause` on Windows
                raise KeyboardInterrupt
    except KeyboardInterrupt:
        t.out("\nStopped.")
    except BaseException as e:
        crash = type(e).__name__
        raise
    finally:
        stop.set()
        beat.finish(crash)
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


def _last_network(store: Store) -> tuple[str, str] | None:
    """(network id, label) of the most recent scan: what 'this network' means,
    the same way `noxis trust` works from the last scan."""
    scan = store.last_scan()
    if not scan:
        return None
    n = scan.get("network", {})
    return n.get("network_id"), n.get("ssid") or n.get("cidr") or n.get("network_id")


def cmd_alerts(args) -> int:
    store = Store()
    cfg = alerts.Config(store.root)
    action = args.action or "list"
    try:
        if action == "list":
            here = _last_network(store)
            print("Alert presets:")
            for name in cfg.names():
                print(f"  {name:<14} {'built in' if name in alerts.BUILTIN else 'yours'}")
            print(f"\nNetworks with trusted devices use '{cfg.defaults['trusted']}', "
                  f"others '{cfg.defaults['untrusted']}'.")
            for net_id, name in cfg.networks.items():
                print(f"  {net_id} uses '{name}'")
            if here:
                trusted = bool(store.network(here[0])["known"])
                print(f"\nThis network ({here[1]}): '{cfg.preset_for(here[0], trusted)}'")
            print(f"\n{len(cfg.mutes)} mute(s). `noxis alerts show NAME` for a preset's rules, "
                  "`noxis mute list` for mutes.")
        elif action == "rules":
            print("Rules (give each a level in a preset: off, log, alert, push):")
            for rule, what in alerts.RULES.items():
                print(f"  {rule:<15} {what}")
            print("\nOne specific finding can also be its own rule, by its name in lowercase with "
                  "dashes,\ne.g. dns-server-changed. alerts.log shows the name of every alert.")
        elif action == "show":
            name = args.name
            if not name:
                here = _last_network(store)
                name = cfg.preset_for(here[0], bool(store.network(here[0])["known"])) if here else "home"
            preset = cfg.preset(name)
            print(f"Preset '{name}'{' (built in)' if name in alerts.BUILTIN else ''}:")
            for rule in alerts.RULES:
                print(f"  {rule:<15} {preset.get(rule, 'off')}")
            for rule, level in preset.items():
                if rule not in alerts.RULES:
                    print(f"  {rule:<15} {level}  (one finding)")
            if "push" in preset.values() and not push.PushConfig(store.root).channels:
                print("\n'push' alerts only show here until you set up push notifications: "
                      "noxis push add ntfy")
        elif action == "new":
            cfg.create(args.name, args.base)
            cfg.save()
            print(f"Created '{args.name}' from '{args.base}'. Change it with "
                  f"`noxis alerts set {args.name} RULE LEVEL`.")
        elif action == "set":
            rule = cfg.set_level(args.name, args.rule, args.level)
            cfg.save()
            print(f"'{args.name}': {rule} is now {args.level}.")
        elif action == "delete":
            cfg.delete(args.name)
            cfg.save()
            print(f"Deleted '{args.name}'.")
        elif action == "use":
            if args.name != "auto" and not cfg.exists(args.name):
                raise ValueError(f"No preset called '{args.name}'.")
            if args.default:
                if args.name == "auto":
                    raise ValueError("Give a preset name with --default.")
                cfg.defaults[args.default] = args.name
                cfg.save()
                print(f"Networks {'with' if args.default == 'trusted' else 'without'} trusted devices "
                      f"now use '{args.name}' unless set otherwise.")
                return 0
            net_id, label = (args.network, args.network) if args.network else (_last_network(store) or (None, None))
            if not net_id:
                raise ValueError("No scan yet, so Noxis doesn't know this network. Run `noxis scan`, "
                                 "or give --network.")
            if args.name == "auto":
                cfg.networks.pop(net_id, None)
                print(f"{label} goes back to the default for its kind of network.")
            else:
                cfg.networks[net_id] = args.name
                print(f"{label} now uses '{args.name}'.")
            cfg.save()
    except (KeyError, ValueError) as e:
        msg = e.args[0] if e.args else str(e)
        print(f"noxis: {msg if isinstance(e, ValueError) else f'No preset called {msg!r}.'}",
              file=sys.stderr)
        return 1
    return 0


def cmd_mute(args) -> int:
    store = Store()
    cfg = alerts.Config(store.root)
    action = args.action or "list"
    if action == "list":
        if not cfg.mutes:
            print("No mutes. Add one with `noxis mute add RULE [--from IP] [--between 02:00-03:00]`.")
        for i, m in enumerate(cfg.mutes, 1):
            print(f"  {i}. {alerts.describe_mute(m)}")
        return 0
    if action == "remove":
        if not 1 <= args.number <= len(cfg.mutes):
            print(f"noxis: there's no mute {args.number} (see `noxis mute list`).", file=sys.stderr)
            return 1
        gone = cfg.mutes.pop(args.number - 1)
        cfg.save()
        print(f"Removed: {alerts.describe_mute(gone)}")
        return 0
    rule = args.rule if args.rule in alerts.RULES else alerts.slug(args.rule)
    if not rule:
        print("noxis: give a rule (see `noxis alerts rules`) or a finding's name.", file=sys.stderr)
        return 1
    mute: dict = {"rule": rule}
    try:
        if args.source:
            from .util import IPV4_RE, normalize_mac
            src = normalize_mac(args.source) or args.source.strip()
            if not (normalize_mac(src) or IPV4_RE.fullmatch(src)):
                raise ValueError(f"'{args.source}' isn't an IP or MAC address.")
            mute["source"] = src
        if args.network:
            net = _last_network(store) if args.network == "this" else (args.network, args.network)
            if not net:
                raise ValueError("No scan yet, so Noxis doesn't know this network. Run `noxis scan`.")
            mute["network"] = net[0]
        if args.between:
            mute["window"] = list(alerts.parse_window(args.between))
    except ValueError as e:
        print(f"noxis: {e}", file=sys.stderr)
        return 1
    if args.note:
        mute["note"] = args.note
    cfg.mutes.append(mute)
    cfg.save()
    print(f"Muted: {alerts.describe_mute(mute)}")
    if rule not in alerts.RULES:
        print(f"  ('{rule}' isn't a rule group, so it matches findings with that name; "
              "see `noxis alerts rules`.)")
    print("Muted alerts are still written to alerts.log, marked as muted.")
    return 0


def cmd_push(args) -> int:
    store = Store()
    cfg = push.PushConfig(store.root)
    action = args.action or "list"
    try:
        if action == "list":
            if not cfg.channels:
                print("No push notifications set up. Add ntfy with: noxis push add ntfy")
            for i, ch in enumerate(cfg.channels, 1):
                print(f"  {i}. {push.describe_channel(ch)}")
            print(f"\nStart/stop messages: {'on' if cfg.startstop else 'off'}. "
                  f"Summary: {push.describe_summary(cfg.summary)}.")
        elif action == "add":
            detail = "minimal" if args.minimal else "full" if args.full else "auto"
            ch = cfg.add_ntfy(args.topic, args.server, args.token, detail)
            cfg.save()
            print(f"Added: {push.describe_channel(ch)}")
            print(f"\nIn the ntfy app, subscribe to the topic\n  {ch['topic']}\non the server\n  {ch['server']}")
            if push.is_public(ch["server"]):
                print("\nOn the public ntfy.sh, the topic name is the password: anyone who knows it "
                      "can read these\nmessages. Keep it private. Messages are minimal (no IPs or "
                      "device names) unless you add --full.")
            print("\nCheck it works: noxis push test")
        elif action == "remove":
            if not 1 <= args.number <= len(cfg.channels):
                raise ValueError(f"there's no channel {args.number} (see `noxis push list`).")
            gone = cfg.channels.pop(args.number - 1)
            cfg.save()
            print(f"Removed: {push.describe_channel(gone)}")
        elif action == "test":
            if not cfg.channels:
                raise ValueError("no push notifications set up yet. Add one: noxis push add ntfy")
            failed = 0
            for i, ch in enumerate(cfg.channels, 1):
                error = push.test_channel(ch)
                failed += bool(error)
                print(f"  {i}. {push.describe_channel(ch).split('  ')[0]}: "
                      + (f"FAILED, {error}" if error else "sent. Check your phone."))
            return 1 if failed else 0
        elif action == "startstop":
            cfg.startstop = args.state == "on"
            cfg.save()
            print(f"Start/stop messages are {args.state}.")
        elif action == "summary":
            cfg.summary = push.parse_summary(" ".join(args.when))
            cfg.save()
            print(f"Summary: {push.describe_summary(cfg.summary)}.")
            if cfg.summary:
                print("If a summary doesn't arrive when expected, Noxis or the machine it runs on "
                      "is down.")
    except ValueError as e:
        print(f"noxis: {e}", file=sys.stderr)
        return 1
    return 0


def _service_monitor_options(options: list[str], root) -> list[str]:
    """Check the monitor options now, so a typo fails here and not at 3 a.m."""
    options = [o for o in options if o != "--"]
    import contextlib
    import io
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            parsed = build_parser().parse_args(["monitor", *options])
    except SystemExit:
        lines = [l for l in err.getvalue().splitlines() if l.strip()]
        raise RuntimeError(f"Those monitor options don't work: "
                           f"{lines[-1].split(': error: ')[-1] if lines else ' '.join(options)}")
    if parsed.preset and not alerts.Config(root).exists(parsed.preset):
        raise RuntimeError(f"No alert preset called '{parsed.preset}'. See `noxis alerts`.")
    return options


def _service_run(args) -> int:
    """What the Windows task runs: `noxis monitor`, logging to service.log."""
    os.environ["NOXIS_SERVICE"] = "1"
    if args.home:
        os.environ["NOXIS_HOME"] = args.home
    root = data_dir()
    log = service.open_log(root)
    sys.stdout = sys.stderr = log
    service.watch_stop_file(root)
    try:
        return main(["monitor", *[o for o in args.monitor_opts if o != "--"]])
    finally:
        log.flush()


def cmd_service(args) -> int:
    if args.action == "run":
        return _service_run(args)
    if why := service.supported():
        raise RuntimeError(f"{why[0].upper()}{why[1:]}.")
    root = data_dir()
    linux = service.IS_LINUX
    action = args.action or "status"
    # Before asking for sudo: nothing to pause or remove if it was never installed.
    if action != "install" and not (service.linux_installed() if linux else service.windows_installed()):
        print("The Noxis service isn't installed. Install it with: noxis service install "
              "[monitor options, e.g. --honeypot]")
        return 0 if action == "status" else 1

    needs_root = linux and action in ("install", "pause", "resume", "uninstall")
    if needs_root and os.geteuid() != 0:
        print(f"`noxis service {action}` changes a system service, so it needs sudo. Running it "
              "with sudo (you may be asked for your password)...", flush=True)
        argv = ["service", action, *(["--user", args.user] if args.user else []),
                *getattr(args, "monitor_opts", [])]
        os.execvp("sudo", service.sudo_argv(argv, root))

    if action == "install":
        options = _service_monitor_options(args.monitor_opts, root)
        command = "noxis monitor " + " ".join(options)
        if linux:
            user = service.linux_service_user(args.user)
            rule = service.linux_install(root, options, user)
        else:
            if args.at_startup:
                print("Windows will ask for your password, so it can start Noxis while nobody is "
                      "logged on. It goes to Windows, not to Noxis.")
            service.windows_install(root, options, args.at_startup)
        service.write_state(root, options=options, installed=datetime.now().isoformat(timespec="seconds"),
                            paused=False, event=None)
        print(f"Noxis service installed and started: {command.strip()}")
        if linux:
            print(f"  Runs as {user}, with only two extra permissions: watching packets (to name "
                  "stealth scanners and spot network sweeps) and decoy ports below 1024.")
            if rule:
                print(f"  {user} may also ask for fresh Wi-Fi scans, to spot evil twins and camera "
                      f"hotspots nearby (that permission only: {rule}).")
            print("  Starts when the computer starts, restarts if it crashes, keeps running after "
                  "you log out.")
        else:
            when = "the computer starts" if args.at_startup else "you log on"
            print(f"  Starts when {when}, with no window. Output: {service.log_path(root)}")
            if args.at_startup:
                print("  Note: started this way, --notify pop-ups won't show (Windows doesn't "
                      "allow it); push notifications still work.")
        print(f"  Uses your settings in {root}: trust, alerts, mutes and push all apply.")
        print("\n  noxis service status    how it's doing\n  noxis service logs      follow its "
              "output\n  noxis service pause     stop until you resume it (stays stopped after a "
              "restart)\n  noxis service uninstall remove it")
        return 0

    if action == "status":
        st = service.linux_status() if linux else service.windows_status()
        state = read = service.read_state(root)
        paused = state.get("paused")
        print(f"Noxis service: {'PAUSED' if paused else ('running' if st['running'] else 'not running')}"
              f"  [{st['state']}]")
        if st.get("since") and st["running"]:
            print(f"  Since: {st['since']}")
        if linux:
            print(f"  Starts at boot: {'yes' if st['starts_on_boot'] else 'no'}"
                  + (f", restarted {st['restarts']} times" if st.get("restarts") not in (None, "0") else ""))
        else:
            print(f"  Starts at {st['trigger']}: {'yes' if st['starts_on_boot'] else 'no (paused)'}")
        print(f"  Runs: noxis monitor {' '.join(read.get('options', []))}".rstrip())
        if paused:
            print("  Resume with: noxis service resume")
        for hint in _linux_hints(wifi_check="--no-wifi" not in read.get("options", [])):
            print(f"  Note: {hint}")
        recent = service.linux_recent_log() if linux else service.tail(service.log_path(root))
        if recent:
            print("\nRecent output:")
            for line in recent:
                print(f"  {line}")
        elif linux:
            print("\n(Can't read its log as you: see it with `noxis service logs`.)")
        return 0

    if action == "logs":
        if linux:
            cmd = ["journalctl", "-u", service.UNIT_NAME, "-f", "-n", "30"]
            if not service.can_read_journal():
                print("Reading the service log needs sudo here (you may be asked for your "
                      "password)...", flush=True)
                cmd = ["sudo", *cmd]
            os.execvp(cmd[0], cmd)
        print(f"Following {service.log_path(root)} (Ctrl+C to stop)")
        try:
            service.follow(service.log_path(root))
        except KeyboardInterrupt:
            pass
        return 0

    if action == "pause":
        if service.read_state(root).get("paused"):
            print("Already paused. Resume with: noxis service resume")
            return 0
        service.write_state(root, paused=True, event="paused")
        if linux:
            service.linux_pause()
        else:
            print("Asking Noxis to stop after its current scan (up to 2 minutes)...", flush=True)
            if not service.windows_pause(root):
                print("  It didn't stop in time, so Windows ended it (no 'paused' notification).")
        print("Paused. It stays paused, even after a restart, until: noxis service resume")
        return 0

    if action == "resume":
        service.write_state(root, paused=False, event="resumed")
        if linux:
            service.linux_resume()
        else:
            service.windows_resume(root)
        print("Resumed: Noxis is watching again.")
        return 0

    if action == "uninstall":
        service.write_state(root, event="removed")  # so its last push says so
        if linux:
            service.linux_uninstall()
        else:
            service.windows_uninstall(root)
        try:
            service.state_path(root).unlink()
        except FileNotFoundError:
            pass
        print("The Noxis service is removed. Your settings and logs are still in "
              f"{root}.")
        return 0
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
    sw.add_argument("--beep", action="store_true", help="terminal beep on honeypot alerts (if your terminal's bell is on)")
    sw.add_argument("--notify", action="store_true", help="desktop notification on honeypot alerts (Windows, or Linux with a desktop)")
    sw.set_defaults(func=cmd_sweep)

    m = sub.add_parser("monitor", help="scan repeatedly and alert on new/risky devices")
    scan_opts(m)
    m.add_argument("--interval", type=int, default=300, help="seconds between scans (default 300)")
    m.add_argument("--deep", nargs="*", metavar="IP",
                   help="check all 65535 ports on every device in the first round, then on each new "
                        "device when it joins (a few minutes each). Give IPs to limit it to those")
    m.add_argument("--deep-connections", type=_connections, metavar="N", help=CONNECTIONS_HELP)
    m.add_argument("--beep", action="store_true", help="terminal beep on alerts (if your terminal's bell is on)")
    m.add_argument("--notify", action="store_true", help="desktop notification on alerts (Windows, or Linux with a desktop)")
    m.add_argument("--honeypot", action="store_true", help="also run decoy services to catch scanners")
    m.add_argument("--ports", help="honeypot decoy ports, comma-separated (default: built-in list)")
    m.add_argument("--lure", action="store_true", help=LURE_HELP)
    m.add_argument("--preset", metavar="NAME",
                   help="alert preset for this run (default: the network's own, see `noxis alerts`)")
    m.add_argument("--remind", type=float, metavar="HOURS",
                   help="repeat alerts for problems still going on after this many hours (default: never)")
    m.set_defaults(func=cmd_monitor)

    al = sub.add_parser("alerts", help="choose what counts as an alert (presets per network)")
    al_sub = al.add_subparsers(dest="action")
    al_sub.add_parser("list", help="presets, which network uses which (default)")
    al_sub.add_parser("rules", help="every rule a preset can set")
    x = al_sub.add_parser("show", help="the levels in one preset")
    x.add_argument("name", nargs="?", help="preset (default: this network's)")
    x = al_sub.add_parser("new", help="make your own preset from an existing one")
    x.add_argument("name")
    x.add_argument("--from", dest="base", default="home", help="preset to copy (default home)")
    x = al_sub.add_parser("set", help="set one rule's level in your preset")
    x.add_argument("name")
    x.add_argument("rule", help="rule (see `noxis alerts rules`) or a finding's name")
    x.add_argument("level", type=_level, metavar="{" + ",".join(alerts.LEVELS) + "}")
    x = al_sub.add_parser("delete", help="delete one of your presets")
    x.add_argument("name")
    x = al_sub.add_parser("use", help="pick the preset for this network (from the last scan)")
    x.add_argument("name", help="preset, or 'auto' to go back to the default")
    x.add_argument("--network", metavar="ID", help="a network id from `noxis known` instead")
    x.add_argument("--default", choices=["trusted", "untrusted"],
                   help="instead set the default for networks with / without trusted devices")
    al.set_defaults(func=cmd_alerts)

    mu = sub.add_parser("mute", help="silence one kind of alert (still logged)")
    mu_sub = mu.add_subparsers(dest="action")
    mu_sub.add_parser("list", help="show mutes (default)")
    x = mu_sub.add_parser("add", help="add a mute")
    x.add_argument("rule", help="rule (see `noxis alerts rules`) or a finding's name")
    x.add_argument("--from", dest="source", metavar="IP_OR_MAC", help="only from this device")
    x.add_argument("--network", metavar="ID", help="only on this network ('this' = the last scan's)")
    x.add_argument("--between", metavar="HH:MM-HH:MM", help="only in this daily time window")
    x.add_argument("--note", help="why (shown in the list)")
    x = mu_sub.add_parser("remove", help="remove a mute by its number in the list")
    x.add_argument("number", type=int)
    mu.set_defaults(func=cmd_mute)

    pu = sub.add_parser("push", help="send alerts to your phone or any device (ntfy)")
    pu_sub = pu.add_subparsers(dest="action")
    pu_sub.add_parser("list", help="where push notifications go (default)")
    x = pu_sub.add_parser("add", help="add a place to send them")
    x.add_argument("service", choices=["ntfy"])
    x.add_argument("topic", nargs="?", help="ntfy topic (default: a new random one)")
    x.add_argument("--server", help="your own ntfy server, e.g. https://pi.example.ts.net "
                                     "(default: the public https://ntfy.sh)")
    x.add_argument("--token", help="ntfy access token, if the server needs one")
    g = x.add_mutually_exclusive_group()
    g.add_argument("--minimal", action="store_true",
                   help="only say what kind of alert, no IPs or device names (default on ntfy.sh)")
    g.add_argument("--full", action="store_true", help="send whole alerts (default on your own server)")
    x = pu_sub.add_parser("remove", help="remove one by its number in the list")
    x.add_argument("number", type=int)
    pu_sub.add_parser("test", help="send a test message to each one now")
    x = pu_sub.add_parser("startstop", help="a message when monitor or honeypot starts and stops")
    x.add_argument("state", choices=["on", "off"])
    x = pu_sub.add_parser("summary", help="a regular 'still watching' summary")
    x.add_argument("when", nargs="+", help="a daily time like 09:00, 'every 6h', 'every 12h from 21:00', or 'off'")
    pu.set_defaults(func=cmd_push)

    sv = sub.add_parser("service", allow_abbrev=False,
                        help="run monitor in the background: at boot (Linux) or logon (Windows)",
                        description="Run `noxis monitor` in the background. Monitor options go after "
                                    "the action, e.g.: noxis service install --honeypot --interval 300")
    sv.add_argument("action", nargs="?", choices=["install", "status", "logs", "pause", "resume",
                                                  "uninstall", "run"],
                    help="install [monitor options] | status (default) | logs | pause | resume | uninstall")
    sv.add_argument("--at-startup", action="store_true",
                    help="Windows: start when the computer starts, not when you log on (asks for your "
                         "Windows password; --notify pop-ups won't show, push still works)")
    sv.add_argument("--user", help="Linux: the account to run as (default: whoever ran sudo)")
    sv.add_argument("--home", help=argparse.SUPPRESS)  # data folder, for `service run`
    sv.set_defaults(func=cmd_service, monitor_opts=[])

    h = sub.add_parser("honeypot", help="run decoy services that alert when anyone touches them")
    h.add_argument("--ports", help="decoy ports, comma-separated (default: built-in list)")
    h.add_argument("--lure", action="store_true", help=LURE_HELP)
    h.add_argument("--bind", help="address to listen on (default 0.0.0.0 = all; 127.0.0.1 to test locally)")
    h.add_argument("--beep", action="store_true", help="terminal beep on alerts (if your terminal's bell is on)")
    h.add_argument("--notify", action="store_true", help="desktop notification on alerts (Windows, or Linux with a desktop)")
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


# Commands that open with the owl banner, and what it says Noxis is doing.
BANNER_STATUS = {"scan": "scanning", "sweep": "sweeping", "monitor": "watching",
                 "honeypot": "watching", "check": "checking"}


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    raw = list(argv if argv is not None else sys.argv[1:])
    if raw[:1] == ["service"]:
        # Everything `service` doesn't know is passed on to `noxis monitor`.
        args, extra = parser.parse_known_args(raw)
        args.monitor_opts = extra
        if extra and args.action not in ("install", "run"):
            parser.error(f"unrecognized arguments: {' '.join(extra)}")
    else:
        args = parser.parse_args(argv)
    if not args.command:
        args = parser.parse_args(["scan", *(argv if argv is not None else sys.argv[1:])])
    if getattr(args, "deep_connections", None) and getattr(args, "deep", None) is None:
        parser.error("--deep-connections only applies together with --deep")
    if args.command in BANNER_STATUS:
        report.banner(report.Term(), BANNER_STATUS[args.command])
    try:
        return args.func(args)
    except (ScanError, RuntimeError, service.ServiceError) as e:
        print(f"noxis: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
