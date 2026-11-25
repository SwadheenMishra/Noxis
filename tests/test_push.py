"""Push notifications through ntfy: sending, bundling, retries, schedule, CLI."""

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
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from noxis import __main__ as cli
from noxis import push
from noxis.alerts import Alert
from noxis.models import Device, NetworkInfo, ScanResult
from noxis.store import Store

NET = NetworkInfo(local_ip="192.168.1.20", prefix=24, cidr="192.168.1.0/24",
                  gateway_ip="192.168.1.1", ssid="HomeNet-5G")
OWN = {"type": "ntfy", "server": "https://pi.example.ts.net", "topic": "noxis-test", "detail": "auto"}
PUBLIC = {"type": "ntfy", "server": "https://ntfy.sh", "topic": "noxis-test", "detail": "auto"}


class FakeNtfy:
    """Records what would be sent; can fail the first N sends."""

    def __init__(self, fail: int = 0):
        self.sent, self.fail, self.lock = [], fail, threading.Lock()

    def __call__(self, ch, title, body, priority, tags):
        with self.lock:
            if self.fail:
                self.fail -= 1
                raise push.PushError("couldn't reach the server (down)")
            self.sent.append({"server": ch["server"], "title": title, "body": body,
                              "priority": priority, "tags": tags})


def msg(text, severity="high"):
    return push.alert_message(Alert("honeypot", "Port scan detected", text, detail="details here",
                                    severity=severity), "HomeNet-5G", host="pi5")


# --------------------------------------------------------------- real HTTP


class NtfyServer(BaseHTTPRequestHandler):
    """Stands in for an ntfy server on this machine."""
    received: list = []
    status = 200

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        NtfyServer.received.append({"path": self.path, "headers": dict(self.headers),
                                    "json": json.loads(body)})
        self.send_response(NtfyServer.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"id":"x1","event":"message"}')

    def log_message(self, *a):
        pass


class SendTests(unittest.TestCase):
    def setUp(self):
        NtfyServer.received, NtfyServer.status = [], 200
        self.server = HTTPServer(("127.0.0.1", 0), NtfyServer)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.ch = {"type": "ntfy", "server": f"http://127.0.0.1:{self.server.server_port}",
                   "topic": "noxis-abc", "token": "tk_secret"}

    def test_publishes_json_with_token(self):
        push.send_ntfy(self.ch, "Noxis: Port scan — 3 ports", "body text", 5, ["rotating_light"])
        got = NtfyServer.received[0]
        self.assertEqual(got["path"], "/")
        self.assertEqual(got["json"], {"topic": "noxis-abc", "title": "Noxis: Port scan — 3 ports",
                                       "message": "body text", "priority": 5,
                                       "tags": ["rotating_light"]})
        self.assertEqual(got["headers"]["Authorization"], "Bearer tk_secret")

    def test_errors_explained(self):
        NtfyServer.status = 401
        with self.assertRaisesRegex(push.PushError, "access token"):
            push.send_ntfy(self.ch, "t", "b", 3, [])

    def test_forbidden_explained_with_and_without_token(self):
        NtfyServer.status = 403
        with self.assertRaisesRegex(push.PushError, "this access token isn't allowed to post to 'noxis-abc'"):
            push.send_ntfy(self.ch, "t", "b", 3, [])
        anon = {k: v for k, v in self.ch.items() if k != "token"}
        with self.assertRaisesRegex(push.PushError, "without a login post to 'noxis-abc'.*--token"):
            push.send_ntfy(anon, "t", "b", 3, [])

    def test_unreachable(self):
        ch = dict(self.ch, server="http://127.0.0.1:1")
        with self.assertRaisesRegex(push.PushError, "couldn't reach"):
            push.send_ntfy(ch, "t", "b", 3, [], timeout=2)

    def test_long_messages_trimmed(self):
        push.send_ntfy(self.ch, "t", "x" * 10000, 3, [])
        self.assertLessEqual(len(NtfyServer.received[0]["json"]["message"].encode()), 4096)


# --------------------------------------------------------------- content


class ContentTests(unittest.TestCase):
    def test_own_server_full_public_minimal(self):
        self.assertEqual(push.detail_for(OWN), "full")
        self.assertEqual(push.detail_for(PUBLIC), "minimal")
        self.assertEqual(push.detail_for(dict(PUBLIC, detail="full")), "full")
        self.assertEqual(push.detail_for(dict(OWN, detail="minimal")), "minimal")

    def test_minimal_has_no_network_details(self):
        m = msg("Port scan detected from 192.168.1.45 (Hikvision, untrusted a0:dd:6c:00:00:02)")
        self.assertIn("192.168.1.45", m.body)
        for secret in ("192.168", "a0:dd", "Hikvision", "HomeNet"):
            self.assertNotIn(secret, m.minimal)
        self.assertIn("Honeypot alert on pi5", m.minimal)

    def test_random_topic(self):
        a, b = push.new_topic(), push.new_topic()
        self.assertNotEqual(a, b)
        self.assertTrue(push.TOPIC_RE.fullmatch(a))
        self.assertGreater(len(a), 25)


# --------------------------------------------------------------- sender


class PusherTests(unittest.TestCase):
    def test_first_alert_at_once_then_bundled(self):
        fake = FakeNtfy()
        p = push.Pusher([OWN], sender=fake, bundle=0.5)
        p.send(msg("one"))
        time.sleep(0.2)
        self.assertEqual(len(fake.sent), 1)  # didn't wait for the bundle window
        p.send(msg("two"))
        p.send(msg("three"))
        p.close()
        self.assertEqual(len(fake.sent), 2)
        self.assertEqual(fake.sent[1]["title"], "Noxis: 2 alerts")
        self.assertIn("two", fake.sent[1]["body"])
        self.assertIn("three", fake.sent[1]["body"])

    def test_status_messages_go_alone(self):
        fake = FakeNtfy()
        p = push.Pusher([OWN], sender=fake, bundle=0.5)
        p.send(push.status_message("Noxis started", "started", "started"))
        p.send(msg("first alert"))  # right after "started": still goes at once
        time.sleep(0.2)
        p.send(msg("second alert"))
        p.send(push.status_message("Noxis stopped", "stopped", "stopped"))
        p.close()
        self.assertEqual([s["title"] for s in fake.sent],
                         ["Noxis started", "Noxis: Port scan detected", "Noxis: Port scan detected",
                          "Noxis stopped"])

    def test_minimal_channel_gets_minimal(self):
        fake = FakeNtfy()
        p = push.Pusher([PUBLIC], sender=fake, bundle=0)
        p.send(msg("from 192.168.1.45"))
        p.close()
        self.assertNotIn("192.168.1.45", fake.sent[0]["body"])

    def test_retries_and_delivers_late(self):
        fake = FakeNtfy(fail=2)
        p = push.Pusher([OWN], sender=fake, bundle=0, retry=[0.1])
        p.send(msg("while down"))
        deadline = time.time() + 5
        while not fake.sent and time.time() < deadline:
            time.sleep(0.05)
        p.close()
        self.assertEqual(len(fake.sent), 1)
        self.assertIn("Couldn't be sent earlier", fake.sent[0]["body"])
        self.assertIn("while down", fake.sent[0]["body"])
        self.assertEqual(p.pending(), 0)

    def test_order_kept_while_down(self):
        fake = FakeNtfy(fail=100)
        p = push.Pusher([OWN], sender=fake, bundle=0, retry=[60])
        for i in range(3):
            p.send(msg(f"alert {i}"))
        time.sleep(0.3)
        self.assertEqual(p.pending(), 3)
        fake.fail = 0
        p.close()  # back up: everything goes out, oldest first
        body = fake.sent[0]["body"]
        self.assertLess(body.index("alert 0"), body.index("alert 2"))

    def test_backlog_is_capped(self):
        p = push.Pusher([OWN], sender=FakeNtfy(fail=10**6), bundle=0)
        for i in range(push.MAX_BACKLOG + 5):
            p._deliver([msg(str(i))])
        self.assertEqual(p.pending(), push.MAX_BACKLOG)
        self.assertEqual(p.dropped, 5)

    def test_one_channel_down_doesnt_block_another(self):
        down, up = FakeNtfy(fail=10**6), FakeNtfy()

        def sender(ch, *a):
            (down if ch is OWN else up)(ch, *a)

        p = push.Pusher([OWN, PUBLIC], sender=sender, bundle=0)
        p._deliver([msg("x")])
        self.assertEqual(len(up.sent), 1)
        self.assertEqual(p.backlog[0][0].body.split("\n")[0], "x")


# --------------------------------------------------------------- schedule


class SummaryTests(unittest.TestCase):
    T = datetime(2026, 11, 25, 9, 2)

    def test_daily(self):
        spec = {"at": "09:00"}
        start = self.T - timedelta(days=2)
        self.assertTrue(push.summary_due(spec, self.T - timedelta(days=1), start, self.T))
        self.assertFalse(push.summary_due(spec, self.T - timedelta(minutes=1), start, self.T))  # sent
        self.assertFalse(push.summary_due(spec, None, start, self.T - timedelta(minutes=5)))  # 08:57
        # Noxis was off at 09:00 and started at 11:00: skip, don't send late.
        self.assertFalse(push.summary_due(spec, None, start, self.T + timedelta(hours=2)))

    def test_every(self):
        spec = {"every": 6}
        self.assertFalse(push.summary_due(spec, None, self.T, self.T + timedelta(hours=5)))
        self.assertTrue(push.summary_due(spec, None, self.T, self.T + timedelta(hours=6)))

    def test_parse(self):
        self.assertEqual(push.parse_summary("9:00"), {"at": "09:00"})
        self.assertEqual(push.parse_summary("every 6h"), {"every": 6})
        self.assertEqual(push.parse_summary("12h"), {"every": 12})
        self.assertEqual(push.parse_summary("every 12h from 21:00"), {"every": 12, "from": "21:00"})
        self.assertEqual(push.parse_summary("every 24h from 7:30"), {"at": "07:30"})
        self.assertIsNone(push.parse_summary("off"))
        for bad in ("25:00", "every 0h", "every 30h", "noon", "every 5h from 21:00",
                    "every 12h from noon"):
            with self.assertRaises(ValueError):
                push.parse_summary(bad)

    def test_every_from(self):
        spec = {"every": 12, "from": "21:00"}
        self.assertEqual(push.summary_times(spec), ["09:00", "21:00"])
        self.assertEqual(push.describe_summary(spec), "every 12h from 21:00 (09:00, 21:00)")
        start = datetime(2026, 11, 24, 12, 0)
        at = lambda h, m=0, d=25: datetime(2026, 11, d, h, m)  # noqa: E731
        self.assertTrue(push.summary_due(spec, at(21, 0, 24), start, at(9, 1)))    # 09:00 slot
        self.assertFalse(push.summary_due(spec, at(9, 1), start, at(15, 0)))       # sent; next at 21:00
        self.assertTrue(push.summary_due(spec, at(9, 1), start, at(21, 0)))        # 21:00 slot
        self.assertFalse(push.summary_due(spec, at(9, 1), start, at(23, 0)))       # 21:00 missed by 2h
        self.assertEqual(push.summary_times({"every": 6, "from": "03:30"}),
                         ["03:30", "09:30", "15:30", "21:30"])


# --------------------------------------------------------------- in Noxis


class TempHome(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = mock.patch.dict(os.environ, {"NOXIS_HOME": tmp.name})
        p.start()
        self.addCleanup(p.stop)
        self.root = Path(tmp.name)

    def configure(self, **kw):
        cfg = push.PushConfig(self.root)
        cfg.channels.append(dict(OWN))
        for k, v in kw.items():
            setattr(cfg, k, v)
        cfg.save()


class AlerterPushTests(TempHome):
    def test_only_push_level_is_pushed(self):
        self.configure()
        fake = FakeNtfy()
        with mock.patch.object(push, "send_ntfy", fake), contextlib.redirect_stdout(io.StringIO()):
            a = cli.Alerter(Store())
            a.pusher.bundle = 0
            a.send(Alert("honeypot", "Port scan detected", "scan from 192.168.1.45"), "wifi:X", True, "X")
            a.send(Alert("device-high", "Camera", "a camera"), "wifi:X", True, "X")  # level alert
            a.close()
        self.assertEqual([s["title"] for s in fake.sent], ["Noxis: Port scan detected"])
        self.assertEqual(fake.sent[0]["priority"], 5)

    def test_no_channels_means_no_pusher(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(cli.Alerter(Store()).pusher)


class MonitorPushTests(TempHome):
    def args(self):
        return argparse.Namespace(target=None, quick=True, no_wifi=True, no_checks=True, interval=0,
                                  deep=None, deep_connections=None, beep=False, notify=False,
                                  honeypot=False, lure=False, ports=None, preset=None, remind=None)

    def run_monitor(self, rounds=1):
        calls = []

        def fake_scan(*a, **kw):
            calls.append(1)
            if len(calls) > rounds:
                raise KeyboardInterrupt
            return ScanResult(network=NET, devices=[Device(ip="192.168.1.1", mac="7c:a9:6b:12:34:56")],
                              started="2026-11-25T12:00:00")

        fake = FakeNtfy()
        out = io.StringIO()
        with mock.patch.object(push, "send_ntfy", fake), mock.patch.object(cli, "run_scan", fake_scan), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            cli.cmd_monitor(self.args())
        return fake, out.getvalue()

    def test_start_and_stop_messages(self):
        self.configure()
        fake, out = self.run_monitor()
        self.assertIn("Push notifications: ntfy", out)
        titles = [s["title"] for s in fake.sent]
        self.assertEqual(titles[0], "Noxis started")
        self.assertEqual(titles[-1], "Noxis stopped")
        self.assertIn("Monitor (scans every 0s)", fake.sent[0]["body"])

    def beat_messages(self, **kw):
        self.configure()
        fake = FakeNtfy()
        with mock.patch.object(push, "send_ntfy", fake), contextlib.redirect_stdout(io.StringIO()):
            a = cli.Alerter(Store())
            a.pusher.bundle = 0
            beat = cli._Heartbeat(a, "Monitor", threading.Event())
            for k, v in kw.items():
                setattr(beat, k, v)
            yield a, beat
            a.close()
        self.sent = fake.sent

    def test_stop_wording_and_crash_priority(self):
        for a, beat in self.beat_messages():
            beat.finish()
        self.assertEqual(self.sent[0]["title"], "Noxis stopped")
        self.assertIn("was stopped (Ctrl+C, or the system shut it down) after 0h 0m", self.sent[0]["body"])
        self.assertEqual(self.sent[0]["priority"], 2)
        for a, beat in self.beat_messages():
            beat.finish("OSError")
        self.assertEqual((self.sent[0]["title"], self.sent[0]["priority"]), ("Noxis crashed", 4))
        self.assertIn("crashed (OSError) after 0h 0m. Details are in errors.log", self.sent[0]["body"])

    def test_first_summary_says_so_far(self):
        for a, beat in self.beat_messages():
            beat.send_summary()
            beat.send_summary()
        self.assertIn("\nSo far: 0 alerts", self.sent[0]["body"])
        self.assertIn("\nSince ", self.sent[1]["body"])  # second one: since the first
        self.assertEqual(self.sent[0]["body"].count("since"), 1)  # only "Running since", no repeat

    def test_startstop_off(self):
        self.configure(startstop=False)
        fake, _ = self.run_monitor()
        self.assertEqual(fake.sent, [])

    def test_summary_contents(self):
        self.configure()
        fake = FakeNtfy()
        with mock.patch.object(push, "send_ntfy", fake), contextlib.redirect_stdout(io.StringIO()):
            a = cli.Alerter(Store())
            a.pusher.bundle = 0
            beat = cli._Heartbeat(a, "Monitor", threading.Event())
            beat.network, beat.devices = "HomeNet-5G", 7
            a.stats.update(rounds=12, alerts=2, pushed=1)
            beat.send_summary()
            a.close()
        body = fake.sent[0]["body"]
        self.assertEqual(fake.sent[0]["title"], "Noxis summary")
        for part in ("Still watching HomeNet-5G", "12 scans", "2 alerts (1 pushed", "7 devices",
                     "Running since"):
            self.assertIn(part, body)
        self.assertEqual(a.stats["rounds"], 0)  # counts restart after each summary
        self.assertTrue((self.root / "push_state.json").exists())

    def test_not_set_up_says_how(self):
        _, out = self.run_monitor()
        self.assertIn("not set up (`noxis push add ntfy`)", out)


class CliTests(TempHome):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def test_add_list_test_remove(self):
        code, out = self.run_cli("push", "add", "ntfy")
        self.assertEqual(code, 0)
        self.assertIn("the topic name is the password", out)  # public server warning
        ch = push.PushConfig(self.root).channels[0]
        self.assertEqual(ch["server"], "https://ntfy.sh")
        self.assertTrue(ch["topic"].startswith("noxis-"))
        self.run_cli("push", "add", "ntfy", "my-topic", "--server", "pi.example.ts.net", "--token", "tk_1")
        self.assertIn("2. ntfy https://pi.example.ts.net/my-topic  (full messages, token)",
                      self.run_cli("push", "list")[1])
        fake = FakeNtfy()
        with mock.patch.object(push, "send_ntfy", fake):
            code, out = self.run_cli("push", "test")
        self.assertEqual((code, len(fake.sent)), (0, 2))
        self.assertEqual(self.run_cli("push", "remove", "1")[0], 0)
        self.assertEqual(len(push.PushConfig(self.root).channels), 1)

    def test_failed_test_is_reported(self):
        self.run_cli("push", "add", "ntfy")
        with mock.patch.object(push, "send_ntfy", FakeNtfy(fail=1)):
            code, out = self.run_cli("push", "test")
        self.assertEqual(code, 1)
        self.assertIn("FAILED, couldn't reach", out)

    def test_settings(self):
        self.assertEqual(self.run_cli("push", "summary", "every", "6h")[0], 0)
        self.assertEqual(push.PushConfig(self.root).summary, {"every": 6})
        self.assertEqual(self.run_cli("push", "startstop", "off")[0], 0)
        self.assertFalse(push.PushConfig(self.root).startstop)
        self.assertEqual(self.run_cli("push", "summary", "noon")[0], 1)
        self.assertEqual(self.run_cli("push", "add", "ntfy", "bad topic!")[0], 1)

    def test_old_level_name_still_works(self):
        self.run_cli("alerts", "new", "mine")
        self.assertEqual(self.run_cli("alerts", "set", "mine", "honeypot", "phone")[0], 0)
        from noxis.alerts import Config
        self.assertEqual(Config(self.root).preset("mine")["honeypot"], "push")

    @unittest.skipUnless(os.name == "posix", "file permissions")
    def test_settings_file_private(self):
        self.run_cli("push", "add", "ntfy", "--token", "tk_1")
        self.assertEqual(os.stat(self.root / "push.json").st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
