"""`noxis sweep --honeypot`: decoy hits during a sweep end up in its report."""

import argparse
import contextlib
import io
import json
import os
import socket
import tempfile
import time
import unittest
from unittest import mock

from noxis import __main__ as cli
from noxis.models import NetworkInfo, ScanResult

NET = NetworkInfo(local_ip="127.0.0.1", prefix=24, cidr="192.168.77.0/24",
                  gateway_ip="192.168.77.1", local_mac="aa:bb:cc:dd:ee:01")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SweepHoneypotTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"NOXIS_HOME": tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.home = tmp.name
        self.port = free_port()

    def args(self, **kw):
        base = dict(rounds=2, wait=0, target=None, quick=True, no_wifi=True, no_checks=True,
                    open=False, honeypot=True, lure=False, ports=str(self.port), beep=False, notify=False,
                    bind="127.0.0.1")
        base.update(kw)
        return argparse.Namespace(**base)

    def sweep(self, args, poke=False):
        def fake_scan(*a, **kw):
            if poke:
                with socket.create_connection(("127.0.0.1", self.port), 3) as s:
                    s.sendall(b"admin\r\n")
                time.sleep(0.8)  # let the decoy log the visit
            return ScanResult(network=NET, devices=[], started="2026-11-23T12:00:00")

        with mock.patch.object(cli, "run_scan", side_effect=fake_scan), \
                mock.patch("noxis.netinfo.get_network_info", return_value=NET), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.cmd_sweep(args)
        with open(os.path.join(self.home, "last_scan.json"), encoding="utf-8") as fh:
            return code, json.load(fh)["findings"]

    def test_hit_is_in_report(self):
        code, findings = self.sweep(self.args(), poke=True)
        self.assertEqual(code, 0)
        hits = [f for f in findings if f["title"].startswith("Honeypot: Connection to decoy")]
        self.assertEqual(len(hits), 1)  # second round's visit is within the cooldown
        self.assertIn("this computer", hits[0]["title"])

    def test_quiet_sweep_says_so(self):
        _, findings = self.sweep(self.args())
        quiet = [f for f in findings if f["title"] == "Honeypot: nobody probed the decoys"]
        self.assertEqual(quiet[0]["severity"], "info")
        self.assertIn(str(self.port), quiet[0]["detail"])

    def test_lure_turns_on_honeypot(self):
        _, findings = self.sweep(self.args(honeypot=False, lure=True))
        self.assertIn("Honeypot: nobody probed the decoys", [f["title"] for f in findings])

    def test_ctrl_c_still_saves_report(self):
        calls = []

        def scan_then_interrupt(*a, **kw):
            calls.append(1)
            if len(calls) == 2:
                raise KeyboardInterrupt
            with socket.create_connection(("127.0.0.1", self.port), 3) as s:
                s.sendall(b"admin\r\n")
            time.sleep(0.8)
            return ScanResult(network=NET, devices=[], started="2026-11-24T05:00:00")

        with mock.patch.object(cli, "run_scan", side_effect=scan_then_interrupt), \
                mock.patch("noxis.netinfo.get_network_info", return_value=NET), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.cmd_sweep(self.args(rounds=4))
        with open(os.path.join(self.home, "last_scan.json"), encoding="utf-8") as fh:
            titles = [f["title"] for f in json.load(fh)["findings"]]
        self.assertEqual(code, 0)
        self.assertIn("Sweep stopped early", titles)
        self.assertTrue(any(t.startswith("Honeypot: Connection to decoy") for t in titles))
        self.assertTrue(os.listdir(os.path.join(self.home, "reports")))

    def test_ctrl_c_before_first_round(self):
        with mock.patch.object(cli, "run_scan", side_effect=KeyboardInterrupt), \
                mock.patch("noxis.netinfo.get_network_info", return_value=NET), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_sweep(self.args()), 130)

    def test_bad_rounds_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_sweep(self.args(rounds=0)), 2)


if __name__ == "__main__":
    unittest.main()
