"""Services inventory: identification, risky services, trust and change detection."""

import asyncio
import json
import os
import socket
import tempfile
import threading
import unittest
from unittest import mock

from noxis import probes, risk, services
from noxis.fingerprint import classify
from noxis.models import Device, NetworkInfo, ScanResult
from noxis.store import Store

SITE = {"kind": "http", "status": "200 OK", "title": "My startup", "server": "nginx/1.22.1"}
SSH = {"kind": "ssh", "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"}


def pi(**banners):
    ports = sorted(int(p) for p in banners) or [22, 8080]
    d = Device(ip="192.168.1.70", mac="88:a2:9e:00:00:01", vendor="Raspberry Pi (Trading) Ltd",
               open_ports=ports, banners={int(k): v for k, v in banners.items()} or {22: SSH, 8080: SITE})
    classify(d)
    d.services = services.identify_all(d)
    return d


def titles(fs):
    return [f.title for f in fs]


class IdentifyTests(unittest.TestCase):
    def test_names(self):
        cases = [
            (8096, {"kind": "http", "title": "Jellyfin"}, "Jellyfin"),
            (8096, {"kind": "http", "status": "302 Found"}, "Probably Jellyfin / Emby"),
            (8123, {"kind": "http", "title": "Home Assistant"}, "Home Assistant"),
            (80, {"kind": "http", "title": "Pi-hole - raspberrypi"}, "Pi-hole"),
            (22, SSH, "SSH (OpenSSH 9.2p1)"),
            (1080, {"kind": "socks", "auth": "none"}, "Open SOCKS proxy"),
            (8080, {"kind": "http", "title": "mitmproxy"}, "mitmproxy (traffic interception)"),
            (445, None, "Windows file sharing (SMB)"),
            (8080, {"kind": "http", "server": "lighttpd"}, "Web server (lighttpd)"),
        ]
        for port, banner, name in cases:
            self.assertEqual(services.identify(port, banner).name, name, (port, banner))

    def test_never_guesses_attack_tools_from_port(self):
        self.assertEqual(services.identify(8080, {"kind": "http", "status": "200 OK"}).name, "Web server")

    def test_fingerprint_ignores_versions(self):
        a = services.identify(8080, SITE).fingerprint
        b = services.identify(8080, dict(SITE, server="nginx/1.26.0")).fingerprint
        self.assertEqual(a, b)
        self.assertNotEqual(a, services.identify(8080, dict(SITE, title="Login")).fingerprint)


class RiskyServiceTests(unittest.TestCase):
    def assess(self, d, trusted=False):
        d.trusted = trusted
        risk.assess_device(d, baseline_exists=False)
        return [(f.severity, f.title) for f in d.findings]

    def test_fake_google_login(self):
        d = pi(**{"80": {"kind": "http", "title": "Sign in - Google Accounts", "password": "yes"}})
        self.assertIn(("high", "Fake Google login page"), self.assess(d))

    def test_evil_portal_on_esp32(self):
        d = Device(ip="192.168.1.77", mac="a0:dd:6c:00:00:01", vendor="Espressif Inc.", open_ports=[80],
                   banners={80: {"kind": "http", "title": "Sign in", "password": "yes", "brand": "Free WiFi"}})
        classify(d)
        d.services = services.identify_all(d)
        self.assertIn(("high", "Fake Free Wifi login page"), self.assess(d))

    def test_router_login_is_not_phishing(self):
        d = Device(ip="192.168.1.1", is_gateway=True, open_ports=[80],
                   banners={80: {"kind": "http", "title": "Wi-Fi login", "password": "yes"}})
        classify(d)
        d.services = services.identify_all(d)
        self.assertNotIn("Fake", " ".join(t for _, t in self.assess(d)))

    def test_interception_tool(self):
        d = pi(**{"8080": {"kind": "http", "title": "mitmproxy"}})
        self.assertIn(("high", "mitmproxy (traffic interception) on the network"), self.assess(d))

    def test_docker_api_is_high(self):
        self.assertIn(("high", "Docker remote API open without a password"), self.assess(pi(**{"2375": {}})))

    def test_open_proxy_and_dns(self):
        d = pi(**{"1080": {"kind": "socks", "auth": "none"}, "53": {}})
        got = self.assess(d)
        self.assertIn(("medium", "Open SOCKS proxy on 192.168.1.70"), got)
        self.assertIn(("medium", "DNS server on a device that isn't your router"), got)
        self.assertEqual(self.assess(pi(**{"1080": {"kind": "socks", "auth": "none"}, "53": {}}),
                                     trusted=True), [])  # your own Pi-hole / proxy


class TrustTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = mock.patch.dict(os.environ, {"NOXIS_HOME": tmp.name})
        p.start()
        self.addCleanup(p.stop)
        self.net = NetworkInfo(local_ip="192.168.1.20", prefix=24, cidr="192.168.1.0/24",
                               gateway_ip="192.168.1.1", ssid="HomeNet-5G")

    def scan(self, d):
        """Record a scan the way `noxis scan` does, then re-annotate a fresh copy."""
        store = Store()
        r = ScanResult(network=self.net, devices=[d], started="2026-11-24T13:00:00")
        store.annotate(r)
        risk.assess_device(d, r.baseline_exists)
        store.record(r)
        return store

    def test_trust_service_with_nickname(self):
        store = self.scan(pi())
        out = store.trust(["192.168.1.70:8080"], "My startup landing page", False)
        self.assertIn("(device trusted too)", " ".join(out))
        d = pi()
        self.scan(d)
        site = next(s for s in d.services if s.port == 8080)
        self.assertTrue(site.trusted)
        self.assertEqual(site.nickname, "My startup landing page")
        self.assertEqual(d.findings, [])

    def test_trusted_site_turning_into_login_page(self):
        store = self.scan(pi())
        store.trust(["192.168.1.70"], None, False)
        Store().trust(["192.168.1.70:8080"], "Landing page", False)
        d = pi(**{"22": SSH, "8080": {"kind": "http", "title": "Sign in - Microsoft", "password": "yes"}})
        self.scan(d)
        got = titles(d.findings)
        self.assertIn("Trusted service changed", got)
        self.assertIn("Fake Microsoft login page", got)
        changed = next(f for f in d.findings if f.title == "Trusted service changed")
        self.assertIn("Landing page", changed.detail)

    def test_new_service_on_trusted_device_is_named(self):
        self.scan(pi())
        Store().trust(["192.168.1.70"], None, False)
        d = pi(**{"22": SSH, "8080": SITE, "8096": {"kind": "http", "title": "Jellyfin"}})
        self.scan(d)
        f = next(f for f in d.findings if f.title == "New service on a trusted device")
        self.assertIn("8096: Jellyfin", f.detail)
        self.assertEqual(f.severity, "medium")

    def test_unknown_service_is_an_error(self):
        self.scan(pi())
        with self.assertRaises(RuntimeError):
            Store().trust(["192.168.1.70:9999"], None, False)

    def test_last_scan_has_services(self):
        self.scan(pi())
        with open(os.path.join(os.environ["NOXIS_HOME"], "last_scan.json"), encoding="utf-8") as fh:
            dev = json.load(fh)["devices"][0]
        self.assertEqual([s["port"] for s in dev["services"]], [22, 8080])


class ProbeTests(unittest.TestCase):
    def test_parse_http_login_and_brand(self):
        raw = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><title>Sign in</title><body>"
               b"<img alt=logo><p>Continue to Gmail</p><input type='password' name=p></body></html>")
        info = probes.parse_http(raw)
        self.assertEqual((info["password"], info["brand"].lower()), ("yes", "gmail"))

    def serve(self, reply: bytes, greet: bool = False) -> int:
        """One-connection server. greet=True: speaks first, like FTP or SSH."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        self.addCleanup(srv.close)

        def run():
            try:
                conn, _ = srv.accept()
                if not greet:
                    conn.recv(16)
                conn.sendall(reply)
                conn.close()
            except OSError:
                pass
        threading.Thread(target=run, daemon=True).start()
        return srv.getsockname()[1]

    def test_socks_open_vs_password(self):
        port = self.serve(b"\x05\x00")
        self.assertEqual(asyncio.run(probes.socks_info("127.0.0.1", port)), {"kind": "socks", "auth": "none"})
        port = self.serve(b"\x05\x02")
        self.assertEqual(asyncio.run(probes.socks_info("127.0.0.1", port))["auth"], "password")

    def test_deep_scan_covers_every_port_once(self):
        seen = []

        async def fake_scan(ips, ports, **kw):
            self.assertIsNone(kw["retry_timeout"])  # no slow retry pass for 65535 ports
            seen.extend(ports)
            return {ip: [p for p in ports if p in (22, 47123)] for ip in ips}

        with mock.patch.object(probes, "scan_ports", fake_scan):
            found = asyncio.run(probes.deep_scan(["192.168.1.70"]))
        self.assertEqual(seen, list(range(1, 65536)))
        self.assertEqual(found, {"192.168.1.70": [22, 47123]})

    def test_unknown_port_gets_probed(self):
        port = self.serve(b"220 custom-daemon ready\r\n", greet=True)
        info = asyncio.run(probes.grab_banners({"127.0.0.1": [port]}))
        self.assertEqual(info["127.0.0.1"][port]["banner"], "220 custom-daemon ready")


if __name__ == "__main__":
    unittest.main()
