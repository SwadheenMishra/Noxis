"""Always-on monitor: shared state, alert presets, mutes, repeat suppression."""

import argparse
import contextlib
import io
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from noxis import __main__ as cli
from noxis import alerts, util
from noxis.alerts import Alert, Config, MonitorState
from noxis.models import Device, Finding, NetworkInfo, ScanResult
from noxis.store import Store, file_lock
from noxis.wifi import AccessPoint

HOME = NetworkInfo(local_ip="192.168.1.20", prefix=24, cidr="192.168.1.0/24",
                   gateway_ip="192.168.1.1", ssid="HomeNet-5G", local_mac="3c:0a:f3:00:00:01")
CAFE = NetworkInfo(local_ip="10.0.0.20", prefix=24, cidr="10.0.0.0/24",
                   gateway_ip="10.0.0.1", ssid="Cafe Guest")
PI = "88:a2:9e:00:00:01"
CAM = "a0:dd:6c:00:00:02"


def dev(ip, mac, *findings, **kw):
    return Device(ip=ip, mac=mac, findings=list(findings), **kw)


def result(net, devices, findings=(), nearby=(), wifi=True, started="2026-11-25T12:00:00"):
    return ScanResult(network=net, devices=list(devices), findings=list(findings),
                      nearby=list(nearby), wifi_scanned=wifi, started=started)


class TempHome(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"NOXIS_HOME": tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = Path(tmp.name)


# ----------------------------------------------------------------- store


class StoreSharingTests(TempHome):
    def test_trust_during_monitor_is_not_overwritten(self):
        monitor = Store()  # loaded once, like a long-running monitor
        monitor.record(result(HOME, [dev("192.168.1.70", PI)]))
        Store().trust(["192.168.1.70"], "pi5", False)  # user, in another terminal
        r = result(HOME, [dev("192.168.1.70", PI)])
        monitor.annotate(r)
        self.assertTrue(r.devices[0].trusted)  # the monitor sees the new trust
        monitor.record(r)
        self.assertIn(PI, Store().network(HOME.network_id)["known"])  # and doesn't erase it

    def test_forget_during_monitor_sticks(self):
        Store().record(result(HOME, [dev("192.168.1.70", PI)]))
        Store().trust(["192.168.1.70"], None, False)
        monitor = Store()
        Store().forget([PI])
        monitor.record(result(HOME, [dev("192.168.1.70", PI)]))
        self.assertNotIn(PI, Store().network(HOME.network_id)["known"])

    def test_lock_is_released_and_stale_locks_ignored(self):
        lock = self.root / "networks.lock"
        with file_lock(lock):
            self.assertTrue(lock.exists())
        self.assertFalse(lock.exists())
        lock.write_text("")
        old = time.time() - 120
        os.utime(lock, (old, old))  # left behind by a crash
        start = time.monotonic()
        with file_lock(lock, timeout=5):
            pass
        self.assertLess(time.monotonic() - start, 1)

    def test_lock_waits_for_holder(self):
        lock = self.root / "networks.lock"
        order = []

        def holder():
            with file_lock(lock):
                order.append("holder")
                time.sleep(0.3)

        t = threading.Thread(target=holder)
        t.start()
        time.sleep(0.1)
        with file_lock(lock):
            order.append("second")
        t.join()
        self.assertEqual(order, ["holder", "second"])


@unittest.skipUnless(hasattr(os, "geteuid"), "sudo only exists on Linux/macOS")
class SudoHomeTests(unittest.TestCase):
    def test_sudo_uses_invoking_users_home(self):
        from noxis import store
        with tempfile.TemporaryDirectory() as home:
            pw = mock.Mock(pw_dir=home)
            env = {k: v for k, v in os.environ.items() if k not in ("NOXIS_HOME", "WARDEN_HOME")}
            env.update(SUDO_USER="alice", SUDO_UID="1000", SUDO_GID="1000")
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch("os.geteuid", return_value=0), \
                    mock.patch("pwd.getpwnam", return_value=pw), \
                    mock.patch("os.chown") as chown, \
                    mock.patch.object(util, "_owner", None):
                path = store.data_dir()
                self.assertEqual(path, Path(home) / ".noxis")
                chown.assert_called_with(path, 1000, 1000)  # handed back to alice

    def test_plain_root_keeps_root_home(self):
        from noxis import store
        env = {k: v for k, v in os.environ.items() if not k.startswith("SUDO_")}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("os.geteuid", return_value=0):
            self.assertIsNone(store._sudo_home())


# ---------------------------------------------------------- presets, mutes


class ConfigTests(TempHome):
    def test_defaults_by_kind_of_network(self):
        cfg = Config(self.root)
        self.assertEqual(cfg.preset_for("wifi:HomeNet-5G", True), "home")
        self.assertEqual(cfg.preset_for("wifi:Cafe Guest", False), "travel")
        cfg.networks["wifi:Cafe Guest"] = "home"
        self.assertEqual(cfg.preset_for("wifi:Cafe Guest", False), "home")

    def test_travel_skips_new_devices_but_not_cameras(self):
        cfg = Config(self.root)
        new = Alert("new-device", "New device joined", "x")
        cam = Alert("device-high", "Camera on the network", "x")
        self.assertEqual(cfg.level(cfg.preset("home"), new), "alert")
        self.assertEqual(cfg.level(cfg.preset("travel"), new), "off")
        self.assertEqual(cfg.level(cfg.preset("travel"), cam), "alert")
        self.assertEqual(cfg.level(cfg.preset("home"), Alert("honeypot", "Port scan", "x")), "phone")

    def test_one_finding_overrides_its_group(self):
        cfg = Config(self.root)
        cfg.create("mine", "home")
        cfg.set_level("mine", "DNS server changed", "phone")
        cfg.save()
        cfg = Config(self.root)
        dns = Alert("network-medium", "DNS server changed", "x")
        other = Alert("network-medium", "Something else", "x")
        self.assertEqual(cfg.level(cfg.preset("mine"), dns), "phone")
        self.assertEqual(cfg.level(cfg.preset("mine"), other), "log")

    def test_builtins_are_read_only_and_deleting_reassigns(self):
        cfg = Config(self.root)
        with self.assertRaises(ValueError):
            cfg.set_level("home", "new-device", "off")
        with self.assertRaises(ValueError):
            cfg.create("home", "travel")
        cfg.create("hotel", "travel")
        cfg.networks["wifi:Hotel"] = "hotel"
        cfg.defaults["untrusted"] = "hotel"
        cfg.delete("hotel")
        self.assertNotIn("wifi:Hotel", cfg.networks)
        self.assertEqual(cfg.defaults["untrusted"], "travel")

    def test_missing_preset_falls_back(self):
        cfg = Config(self.root)
        cfg.networks["wifi:X"] = "gone"
        self.assertEqual(cfg.preset_for("wifi:X", True), "home")


class MuteTests(unittest.TestCase):
    SWEEP = Alert("network-sweep", "Network sweep detected", "x", src_ip="192.168.1.1",
                  src_mac="7c:a9:6b:12:34:56")

    def match(self, mute, alert=SWEEP, net="wifi:HomeNet-5G", at="02:30"):
        now = datetime(2026, 11, 25, *map(int, at.split(":")))
        return alerts.mute_matches(mute, alert, net, now)

    def test_rule_group_or_name(self):
        self.assertTrue(self.match({"rule": "network-sweep"}))
        self.assertTrue(self.match({"rule": "network-sweep-detected"}))
        self.assertFalse(self.match({"rule": "honeypot"}))

    def test_source_by_ip_or_mac(self):
        self.assertTrue(self.match({"rule": "network-sweep", "source": "192.168.1.1"}))
        self.assertTrue(self.match({"rule": "network-sweep", "source": "7c:a9:6b:12:34:56"}))
        self.assertFalse(self.match({"rule": "network-sweep", "source": "192.168.1.70"}))
        # A router that's been swapped (different MAC, same IP) isn't covered by a MAC mute.
        self.assertFalse(self.match({"rule": "network-sweep", "source": "7c:a9:6b:99:99:99"}))

    def test_network_and_window(self):
        m = {"rule": "network-sweep", "network": "wifi:HomeNet-5G", "window": ["02:00", "03:00"]}
        self.assertTrue(self.match(m))
        self.assertFalse(self.match(m, at="03:00"))
        self.assertFalse(self.match(m, net="wifi:Cafe Guest"))

    def test_window_across_midnight(self):
        m = {"rule": "network-sweep", "window": ["23:00", "01:00"]}
        self.assertTrue(self.match(m, at="23:30"))
        self.assertTrue(self.match(m, at="00:30"))
        self.assertFalse(self.match(m, at="12:00"))

    def test_parse_window(self):
        self.assertEqual(alerts.parse_window("2:00-3:30"), ("02:00", "03:30"))
        for bad in ("24:00-01:00", "02:60-03:00", "2-3", ""):
            with self.assertRaises(ValueError):
                alerts.parse_window(bad)


# ------------------------------------------------------- repeat suppression


class RepeatTests(TempHome):
    def setUp(self):
        super().setUp()
        self.state = MonitorState.load(self.root)
        self.t0 = datetime(2026, 11, 25, 12, 0)

    def round(self, findings_by_mac, present=None, wifi=True, minutes=0, remind=None):
        found = [Alert("device-high", t, t, key=f"{mac}|{t}", device=mac, scope="device")
                 for mac, titles in findings_by_mac.items() for t in titles]
        present = set(findings_by_mac) if present is None else present
        fired = self.state.update("wifi:HomeNet-5G", found, present, wifi, remind,
                                  now=self.t0 + timedelta(minutes=minutes))
        return [a.title for a in fired]

    def test_appear_persist_rearm(self):
        self.assertEqual(self.round({CAM: ["Camera"]}), ["Camera"])
        self.assertEqual(self.round({CAM: ["Camera"]}, minutes=5), [])  # still there: quiet
        for i in range(1, alerts.REARM_ROUNDS + 1):  # fixed, while the device is online
            self.assertEqual(self.round({}, present={CAM}, minutes=5 + i * 5), [])
        self.assertEqual(self.round({CAM: ["Camera"]}, minutes=60), ["Camera"])  # back: alert again

    def test_not_rearmed_too_soon(self):
        self.round({CAM: ["Camera"]})
        self.round({}, present={CAM}, minutes=5)
        self.assertEqual(self.round({CAM: ["Camera"]}, minutes=10), [])

    def test_sleeping_device_doesnt_rearm(self):
        self.round({CAM: ["Camera"]})
        for i in range(1, 6):
            self.round({}, present=set(), minutes=i * 5)  # camera asleep
        self.assertEqual(self.round({CAM: ["Camera"]}, minutes=40), [])

    def test_wifi_problems_wait_for_a_wifi_scan(self):
        ev = [Alert("wifi-high", "Open copy", "x", key="aa|Open copy", scope="wifi")]
        net = "wifi:HomeNet-5G"
        self.assertEqual(len(self.state.update(net, ev, set(), True, now=self.t0)), 1)
        for i in range(5):
            self.state.update(net, [], set(), False, now=self.t0)  # Wi-Fi scan failed
        self.assertEqual(self.state.update(net, ev, set(), True, now=self.t0), [])

    def test_reminder(self):
        self.round({CAM: ["Camera"]}, remind=6)
        self.assertEqual(self.round({CAM: ["Camera"]}, minutes=60, remind=6), [])
        fired = self.state.update(
            "wifi:HomeNet-5G", [Alert("device-high", "Camera", "Camera", key=f"{CAM}|Camera",
                                      device=CAM, scope="device")],
            {CAM}, True, 6, now=self.t0 + timedelta(hours=6))
        self.assertTrue(fired and fired[0].reminder)

    def test_mac_missing_in_one_round_is_the_same_problem(self):
        net = "wifi:HomeNet-5G"

        def pi(mac):
            return [Alert("device-medium", "Raspberry Pi", "x", key=f"{mac or '192.168.1.70'}|Raspberry Pi",
                          src_ip="192.168.1.70", device=mac, scope="device")]

        self.assertEqual(len(self.state.update(net, pi(PI), {PI}, True, now=self.t0)), 1)
        self.assertEqual(self.state.update(net, pi(None), set(), True, now=self.t0), [])  # no ARP reply
        self.assertEqual(self.state.update(net, pi(PI), {PI}, True, now=self.t0), [])
        # And the other way round: first seen without its MAC.
        state = MonitorState.load(self.root / "other")
        self.assertEqual(len(state.update(net, pi(None), set(), True, now=self.t0)), 1)
        self.assertEqual(state.update(net, pi(PI), {PI}, True, now=self.t0), [])
        self.assertEqual(list(state.data["networks"][net]["active"]), [f"{PI}|Raspberry Pi"])

    def test_survives_restart(self):
        self.round({CAM: ["Camera"]})
        self.state.save()
        self.state = MonitorState.load(self.root)  # monitor restarted
        self.assertEqual(self.round({CAM: ["Camera"]}, minutes=5), [])


class NewDeviceTests(TempHome):
    def new(self, state, net, devices):
        r = result(net, devices)
        store = Store()
        store.annotate(r)
        store.record(r)
        cands, _ = alerts.from_result(r)
        return [a.src_mac for a in state.new_devices(net.network_id, r, cands)]

    def test_first_ever_round_is_baseline(self):
        state = MonitorState.load(self.root)
        self.assertEqual(self.new(state, HOME, [dev("192.168.1.70", PI)]), [])
        self.assertEqual(self.new(state, HOME, [dev("192.168.1.70", PI), dev("192.168.1.45", CAM)]),
                         [CAM])

    def test_device_that_joined_while_monitor_was_off(self):
        state = MonitorState.load(self.root)
        self.new(state, HOME, [dev("192.168.1.70", PI)])
        state.save()
        state = MonitorState.load(self.root)  # restart; the camera joined meanwhile
        self.assertEqual(self.new(state, HOME, [dev("192.168.1.70", PI), dev("192.168.1.45", CAM)]),
                         [CAM])

    def test_first_monitor_on_a_scanned_network_uses_scan_history(self):
        Store().record(result(HOME, [dev("192.168.1.70", PI)]))  # an earlier `noxis scan`
        state = MonitorState.load(self.root)
        self.assertEqual(self.new(state, HOME, [dev("192.168.1.70", PI), dev("192.168.1.45", CAM)]),
                         [CAM])

    def test_roaming_laptop(self):
        state = MonitorState.load(self.root)
        self.new(state, HOME, [dev("192.168.1.70", PI)])
        strangers = [dev(f"10.0.0.{i}", f"02:00:00:00:00:{i:02x}") for i in range(2, 30)]
        self.assertEqual(self.new(state, CAFE, strangers), [])  # a new network is a baseline
        self.assertEqual(self.new(state, HOME, [dev("192.168.1.70", PI)]), [])  # home again


# ------------------------------------------------------------ the monitor


class AlerterTests(TempHome):
    def send(self, alert, net_id="wifi:HomeNet-5G", trusted_network=True):
        out = io.StringIO()
        alerter = cli.Alerter(Store())
        alerter.term.out = lambda s: out.write(s + "\n")
        level = alerter.send(alert, net_id, trusted_network, "HomeNet-5G")
        log = (self.root / "alerts.log").read_text(encoding="utf-8") if (self.root / "alerts.log").exists() else ""
        return level, out.getvalue(), log

    def test_alert_level_shows_and_logs_with_rule(self):
        level, term, log = self.send(Alert("device-high", "Camera on the network", "192.168.1.45: Camera"))
        self.assertEqual(level, "alert")
        self.assertIn("192.168.1.45: Camera", term)
        self.assertIn("[device-high | camera-on-the-network]", log)

    def test_log_level_is_silent(self):
        level, term, log = self.send(Alert("device-medium", "Not trusted", "192.168.1.45: Not trusted"))
        self.assertEqual((level, term), ("log", ""))
        self.assertIn("Not trusted", log)

    def test_off_level_does_nothing(self):
        level, term, log = self.send(Alert("new-device", "New device joined", "x"), trusted_network=False)
        self.assertEqual((level, term, log), ("off", "", ""))

    def test_muted_is_logged_as_muted(self):
        cfg = Config(self.root)
        cfg.mutes.append({"rule": "network-sweep", "source": "192.168.1.1"})
        cfg.save()
        level, term, log = self.send(Alert("network-sweep", "Network sweep detected", "sweep",
                                           src_ip="192.168.1.1"))
        self.assertEqual((level, term), ("muted", ""))
        self.assertIn("(muted: network-sweep from 192.168.1.1)", log)


class MonitorLoopTests(TempHome):
    def args(self, **kw):
        base = dict(target=None, quick=True, no_wifi=True, no_checks=True, interval=0, deep=None,
                    deep_connections=None, beep=False, notify=False, honeypot=False, lure=False,
                    ports=None, preset=None, remind=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def run_monitor(self, rounds, args=None):
        """Each item: a ScanResult to return, or an exception to raise."""
        it = iter(rounds)

        def fake_scan(*a, **kw):
            try:
                item = next(it)
            except StopIteration:
                raise KeyboardInterrupt
            if isinstance(item, BaseException):
                raise item
            return item

        out = io.StringIO()
        # Keep the findings each test sets (normally risk.assess_device recomputes them).
        with mock.patch.object(cli, "run_scan", side_effect=fake_scan), \
                mock.patch.object(cli.risk, "assess_device", lambda d, baseline: None), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.cmd_monitor(args or self.args())
        log = self.root / "alerts.log"
        return code, out.getvalue(), log.read_text(encoding="utf-8") if log.exists() else ""

    def trust_pi(self):
        Store().record(result(HOME, [dev("192.168.1.70", PI)]))
        Store().trust(["192.168.1.70"], None, False)  # home: a network with trusted devices

    def test_unexpected_error_doesnt_stop_the_monitor(self):
        self.trust_pi()
        r1 = result(HOME, [dev("192.168.1.70", PI)])
        r2 = result(HOME, [dev("192.168.1.70", PI), dev("192.168.1.45", CAM)])
        code, out, log = self.run_monitor([r1, ValueError("parser broke"), r2])
        self.assertEqual(code, 0)
        self.assertIn("round failed (ValueError: parser broke)", out)
        self.assertIn("ValueError: parser broke", (self.root / "errors.log").read_text(encoding="utf-8"))
        self.assertIn(f"New device joined: 192.168.1.45", log)  # the round after still ran

    def test_restart_doesnt_repeat_alerts(self):
        cam = dev("192.168.1.45", CAM, Finding("high", "Camera on the network"))
        _, _, log1 = self.run_monitor([result(HOME, [cam]), result(HOME, [cam])])
        self.assertEqual(log1.count("Camera on the network"), 1)
        _, _, log2 = self.run_monitor([result(HOME, [cam])])  # restarted
        self.assertEqual(log2.count("Camera on the network"), 1)

    def test_untrusted_network_uses_travel(self):
        Store().record(result(CAFE, [dev("10.0.0.2", "02:00:00:00:00:02")]))
        rounds = [result(CAFE, [dev("10.0.0.2", "02:00:00:00:00:02")]),
                  result(CAFE, [dev("10.0.0.2", "02:00:00:00:00:02"), dev("10.0.0.3", "02:00:00:00:00:03")])]
        _, out, log = self.run_monitor(rounds)
        self.assertIn("alert preset 'travel'", out)
        self.assertNotIn("New device joined", log)

    def test_nearby_wifi_alert(self):
        ap = AccessPoint(ssid="HDWiFiCam-8812", bssid="00:c0:ca:aa:bb:cc", signal=80, auth="Open")
        _, _, log = self.run_monitor([result(HOME, [], nearby=[ap])])
        self.assertIn("Nearby Wi-Fi 'HDWiFiCam-8812': Camera-style Wi-Fi hotspot nearby", log)

    def test_unknown_preset_refused(self):
        with self.assertRaises(RuntimeError):
            cli.cmd_monitor(self.args(preset="nope"))


class HoneypotLiveTests(TempHome):
    def test_trust_while_running_is_picked_up(self):
        Store().record(result(HOME, [dev("192.168.1.70", PI)]))
        with mock.patch("noxis.netinfo.get_network_info", return_value=HOME), \
                mock.patch("noxis.discovery.read_arp_table", return_value={"192.168.1.70": PI}):
            live = cli._LiveNetwork(Store())
            self.assertFalse(live.describe("192.168.1.70")[1])
            Store().trust(["192.168.1.70"], "pi5", False)
            who, trusted, mac = live.describe("192.168.1.70")
        self.assertTrue(trusted)
        self.assertIn("pi5", who)
        self.assertEqual(mac, PI)

    def test_new_address_is_followed(self):
        from noxis.honeypot import Honeypot, HoneypotEvent
        moved = NetworkInfo(local_ip="192.168.1.21", prefix=24, cidr="192.168.1.0/24",
                            gateway_ip="192.168.1.1", ssid="HomeNet-5G", local_mac="3c:0a:f3:00:00:01")
        hp = Honeypot(HOME.local_ip, HOME.local_mac, lambda a: None, ports=[])
        with mock.patch("noxis.netinfo.get_network_info", side_effect=[HOME, moved]):
            live = cli._LiveNetwork(Store())
            live.refresh(hp)
        self.assertEqual((hp.local_ip, live.net.local_ip), ("192.168.1.21", "192.168.1.21"))
        self.assertEqual(hp.detector.own_ips, {"192.168.1.21"})
        # The old address may belong to someone else now: its scans count again.
        alerts_ = [hp.detector.handle(HoneypotEvent(i, "syn", "192.168.1.20", dst_port=i))
                   for i in range(1, 12)]
        self.assertTrue(any(alerts_))

    def test_refresh_keeps_last_view_when_network_is_down(self):
        with mock.patch("noxis.netinfo.get_network_info", side_effect=[HOME, OSError("down")]):
            live = cli._LiveNetwork(Store())
            live.refresh()
        self.assertEqual(live.net, HOME)


@unittest.skipUnless(hasattr(os, "geteuid"), "Linux desktop notifications")
class LinuxNotifyTests(unittest.TestCase):
    def cmd(self, env, euid=1000, bus_exists=False, has_tool=True):
        clean = {k: v for k, v in os.environ.items()
                 if not k.startswith("SUDO_") and k != "DBUS_SESSION_BUS_ADDRESS"}
        clean.update(env)
        with mock.patch.dict(os.environ, clean, clear=True), \
                mock.patch("os.geteuid", return_value=euid), mock.patch("os.getuid", return_value=euid), \
                mock.patch("os.path.exists", return_value=bus_exists), \
                mock.patch("shutil.which", return_value="/usr/bin/notify-send" if has_tool else None):
            return cli._linux_notify_cmd("Noxis alert", "Port scan"), cli.notify_problem()

    def test_desktop_user(self):
        cmd, problem = self.cmd({"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"})
        self.assertEqual(cmd[:2], ["env", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"])
        self.assertIn("Port scan", cmd)
        if sys_is_linux():
            self.assertIsNone(problem)

    def test_under_sudo_goes_to_the_users_desktop(self):
        cmd, _ = self.cmd({"SUDO_USER": "alice", "SUDO_UID": "1000"}, euid=0, bus_exists=True)
        self.assertEqual(cmd[:5], ["sudo", "-u", "alice", "env",
                                   "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"])

    def test_ssh_only_machine(self):
        cmd, problem = self.cmd({}, bus_exists=False)
        self.assertIsNone(cmd)
        if sys_is_linux():
            self.assertIn("no desktop session", problem)

    def test_missing_notify_send(self):
        cmd, problem = self.cmd({"DBUS_SESSION_BUS_ADDRESS": "x"}, has_tool=False)
        self.assertIsNone(cmd)
        if sys_is_linux():
            self.assertIn("libnotify-bin", problem)


def sys_is_linux():
    import sys
    return sys.platform.startswith("linux")


class NotifyFallbackTests(TempHome):
    def test_notify_turns_itself_off_with_a_reason(self):
        out = io.StringIO()
        with mock.patch.object(cli, "notify_problem", return_value="no desktop here"), \
                contextlib.redirect_stdout(out):
            alerter = cli.Alerter(Store(), notify=True)
        self.assertFalse(alerter.notify)
        self.assertIn("--notify is off: no desktop here", out.getvalue())


class CliTests(TempHome):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def test_preset_and_mute_round_trip(self):
        self.assertEqual(self.run_cli("alerts", "new", "hotel", "--from", "travel")[0], 0)
        self.assertEqual(self.run_cli("alerts", "set", "hotel", "honeypot", "alert")[0], 0)
        Store().record(result(CAFE, []))
        self.assertEqual(self.run_cli("alerts", "use", "hotel")[0], 0)
        code, out = self.run_cli("mute", "add", "network-sweep", "--from", "10.0.0.1",
                                 "--network", "this", "--between", "02:00-03:00")
        self.assertEqual(code, 0)
        data = json.loads((self.root / "alerts.json").read_text(encoding="utf-8"))
        self.assertEqual(data["networks"], {CAFE.network_id: "hotel"})
        self.assertEqual(data["presets"]["hotel"]["honeypot"], "alert")
        self.assertEqual(data["mutes"], [{"rule": "network-sweep", "source": "10.0.0.1",
                                          "network": CAFE.network_id, "window": ["02:00", "03:00"]}])
        self.assertIn("1. network-sweep from 10.0.0.1", self.run_cli("mute", "list")[1])
        self.assertEqual(self.run_cli("mute", "remove", "1")[0], 0)
        self.assertEqual(Config(self.root).mutes, [])

    def test_bad_input(self):
        self.assertEqual(self.run_cli("alerts", "set", "home", "new-device", "off")[0], 1)
        self.assertEqual(self.run_cli("alerts", "show", "nope")[0], 1)
        self.assertEqual(self.run_cli("mute", "add", "honeypot", "--from", "not-an-ip")[0], 1)
        self.assertEqual(self.run_cli("mute", "remove", "3")[0], 1)
        self.assertEqual(self.run_cli("alerts", "use", "home")[0], 1)  # no scan yet


if __name__ == "__main__":
    unittest.main()
