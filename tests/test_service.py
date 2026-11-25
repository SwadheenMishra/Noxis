"""`noxis service`: the systemd unit, the Windows task, and the commands."""

import contextlib
import io
import os
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from noxis import __main__ as cli
from noxis import push, service
from noxis.store import Store

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


class TempHome(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = mock.patch.dict(os.environ, {"NOXIS_HOME": tmp.name})
        p.start()
        self.addCleanup(p.stop)
        self.root = Path(tmp.name)

    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = cli.main(list(argv))
        return code, out.getvalue()


class UnitFileTests(unittest.TestCase):
    def test_runs_as_user_with_two_capabilities(self):
        unit = service.systemd_unit("alice", "/home/alice/.noxis", "/usr/bin/python3",
                                    ["--honeypot", "--interval", "300"])
        self.assertIn("User=alice", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE", unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("Environment=NOXIS_HOME=/home/alice/.noxis", unit)
        self.assertIn("Environment=NOXIS_SERVICE=1", unit)
        self.assertIn("ExecStart=/usr/bin/python3 -m noxis monitor --honeypot --interval 300", unit)
        self.assertIn("After=network-online.target", unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertNotIn("User=root", unit)

    def test_options_are_quoted(self):
        unit = service.systemd_unit("alice", "/h", "/usr/bin/python3", ["--preset", "my home"])
        self.assertIn("--preset 'my home'", unit)

    def test_service_user(self):
        with mock.patch.dict(os.environ, {"SUDO_USER": "alice"}):
            self.assertEqual(service.linux_service_user(None), "alice")
            self.assertEqual(service.linux_service_user("bob"), "bob")
        env = {k: v for k, v in os.environ.items() if k != "SUDO_USER"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(service.ServiceError, "not root"):
                service.linux_service_user(None)

    def test_sudo_keeps_data_folder(self):
        argv = service.sudo_argv(["service", "install", "--honeypot"], "/home/alice/.noxis")
        self.assertEqual(argv[:3], ["sudo", "env", "NOXIS_HOME=/home/alice/.noxis"])
        self.assertEqual(argv[-3:], ["service", "install", "--honeypot"])


class TaskXmlTests(unittest.TestCase):
    def parse(self, at_startup):
        xml = service.task_xml(Path(r"C:\Users\a\.noxis"), ["--honeypot", "--preset", "my home"],
                               at_startup, r"PC\a")
        return ET.fromstring(xml.split("?>", 1)[1])

    def test_logon_task(self):
        t = self.parse(False)
        self.assertIsNotNone(t.find(".//t:LogonTrigger", NS))
        self.assertEqual(t.find(".//t:LogonType", NS).text, "InteractiveToken")
        self.assertEqual(t.find(".//t:RunLevel", NS).text, "LeastPrivilege")
        self.assertEqual(t.find(".//t:ExecutionTimeLimit", NS).text, "PT0S")  # never killed for running long
        self.assertEqual(t.find(".//t:StopIfGoingOnBatteries", NS).text, "false")
        args = t.find(".//t:Arguments", NS).text
        self.assertIn(r"--home=C:\Users\a\.noxis", args)
        self.assertIn('-- --honeypot --preset "my home"', args)

    def test_startup_task(self):
        t = self.parse(True)
        self.assertIsNotNone(t.find(".//t:BootTrigger", NS))
        self.assertEqual(t.find(".//t:LogonType", NS).text, "Password")


class CommandTests(TempHome):
    def test_bad_options_rejected_before_install(self):
        with mock.patch.object(service, "linux_install") as li, \
                mock.patch.object(service, "windows_install") as wi, \
                mock.patch("os.geteuid", create=True, return_value=0):
            code, out = self.run_cli("service", "install", "--intervl", "5")
        self.assertEqual(code, 1)
        self.assertIn("monitor options don't work", out)
        li.assert_not_called()
        wi.assert_not_called()

    def test_install_records_options(self):
        with mock.patch.multiple(service, IS_LINUX=False, IS_WINDOWS=True), \
                mock.patch.object(service, "windows_install") as wi:
            code, out = self.run_cli("service", "install", "--honeypot", "--interval", "120")
        self.assertEqual(code, 0)
        wi.assert_called_once()
        self.assertEqual(wi.call_args[0][1], ["--honeypot", "--interval", "120"])
        self.assertEqual(service.read_state(self.root)["options"], ["--honeypot", "--interval", "120"])
        self.assertIn("Starts when you log on", out)

    def test_at_startup_warns_about_notify(self):
        with mock.patch.multiple(service, IS_LINUX=False, IS_WINDOWS=True), mock.patch.object(service, "windows_install"):
            _, out = self.run_cli("service", "install", "--at-startup")
        self.assertIn("--notify pop-ups won't show", out)
        self.assertIn("push notifications still work", out)

    def test_linux_asks_for_sudo(self):
        with mock.patch.object(service, "IS_LINUX", True), \
                mock.patch("os.geteuid", create=True, return_value=1000), \
                mock.patch("os.execvp", side_effect=SystemExit(0)) as ex:
            with self.assertRaises(SystemExit):
                self.run_cli("service", "pause")
        self.assertEqual(ex.call_args[0][1][:2], ["sudo", "env"])
        self.assertEqual(ex.call_args[0][1][-2:], ["service", "pause"])

    def test_pause_resume_state(self):
        with mock.patch.multiple(service, IS_LINUX=False, IS_WINDOWS=True), \
                mock.patch.object(service, "windows_installed", return_value=True), \
                mock.patch.object(service, "windows_pause", return_value=True), \
                mock.patch.object(service, "windows_resume"):
            self.run_cli("service", "pause")
            self.assertEqual(service.read_state(self.root), {"paused": True, "event": "paused"})
            self.assertIn("Already paused", self.run_cli("service", "pause")[1])
            self.run_cli("service", "resume")
        self.assertEqual(service.read_state(self.root), {"paused": False, "event": "resumed"})

    def test_not_installed(self):
        with mock.patch.multiple(service, IS_LINUX=False, IS_WINDOWS=True), \
                mock.patch.object(service, "windows_installed", return_value=False):
            code, out = self.run_cli("service", "status")
        self.assertEqual(code, 0)
        self.assertIn("isn't installed", out)

    def test_extra_options_only_for_install(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["service", "status", "--honeypot"])


class HeartbeatServiceTests(TempHome):
    def messages(self, event, crash=None):
        cfg = push.PushConfig(self.root)
        cfg.channels.append({"type": "ntfy", "server": "https://pi.example", "topic": "t"})
        cfg.save()
        service.write_state(self.root, event=event)
        sent = []
        with mock.patch.dict(os.environ, {"NOXIS_SERVICE": "1"}), \
                mock.patch.object(push, "send_ntfy", lambda ch, t, b, p, tags: sent.append(t)), \
                contextlib.redirect_stdout(io.StringIO()):
            a = cli.Alerter(Store())
            a.pusher.bundle = 0
            beat = cli._Heartbeat(a, "Monitor", threading.Event())
            beat.start()
            beat.finish(crash)
        return sent

    def test_resumed_then_paused(self):
        self.assertEqual(self.messages("resumed"), ["Noxis resumed", "Noxis stopped"])

    def test_paused(self):
        self.assertEqual(self.messages("paused")[-1], "Noxis paused")

    def test_removed(self):
        self.assertEqual(self.messages("removed")[-1], "Noxis service removed")

    def test_crash_wins(self):
        self.assertEqual(self.messages("paused", crash="OSError")[-1], "Noxis crashed")

    def test_only_as_a_service(self):
        service.write_state(self.root, event="paused")
        self.assertEqual(service.read_state(self.root)["event"], "paused")
        sent = []
        cfg = push.PushConfig(self.root)
        cfg.channels.append({"type": "ntfy", "server": "https://pi.example", "topic": "t"})
        cfg.save()
        env = {k: v for k, v in os.environ.items() if k != "NOXIS_SERVICE"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(push, "send_ntfy", lambda ch, t, b, p, tags: sent.append(t)), \
                contextlib.redirect_stdout(io.StringIO()):
            a = cli.Alerter(Store())
            a.pusher.bundle = 0
            beat = cli._Heartbeat(a, "Monitor", threading.Event())
            beat.finish()
        self.assertEqual(sent, ["Noxis stopped"])  # a manual run isn't "paused"


class StopFileTests(TempHome):
    def test_stop_file_sets_stop(self):
        service.STOP.clear()
        self.addCleanup(service.STOP.clear)
        service.watch_stop_file(self.root)
        service.stop_file(self.root).write_text("stop")
        self.assertTrue(service.STOP.wait(5))
        self.assertFalse(service.stop_file(self.root).exists())

    def test_log_rotation(self):
        log = service.log_path(self.root)
        log.write_bytes(b"x" * (service.LOG_LIMIT + 1))
        fh = service.open_log(self.root)
        fh.close()
        self.assertTrue(log.with_suffix(".log.old").exists())
        self.assertLess(log.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
