import socket
import struct
import unittest

import threading
import time

from noxis import honeypot
from noxis.honeypot import Detector, HoneypotEvent, frame_to_event, parse_frame

MAC_A = bytes.fromhex("aabbcc000001")
MAC_B = bytes.fromhex("aabbcc000002")


def ether(etype: int, payload: bytes, src=MAC_A, dst=b"\xff" * 6) -> bytes:
    return dst + src + struct.pack("!H", etype) + payload


def arp_request(sender_ip: str, target_ip: str, sender_mac=MAC_A) -> bytes:
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sender_mac + socket.inet_aton(sender_ip) \
        + b"\x00" * 6 + socket.inet_aton(target_ip)
    return ether(0x0806, body, src=sender_mac)


def tcp_syn(src: str, dst: str, dport: int, flags: int = 0x02) -> bytes:
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack("!HHIIBBHHH", 40000, dport, 0, 0, 0x50, flags, 1024, 0, 0)
    return ether(0x0800, ip + tcp, dst=MAC_B)


class ParseTests(unittest.TestCase):
    def test_arp(self):
        p = parse_frame(arp_request("192.168.1.77", "192.168.1.10"))
        self.assertEqual(p, ("arp", 1, "aa:bb:cc:00:00:01", "192.168.1.77", "192.168.1.10"))

    def test_syn_to_us_becomes_event(self):
        ev = frame_to_event(tcp_syn("192.168.1.77", "192.168.1.70", 3306), "192.168.1.70", 1.0)
        self.assertEqual((ev.kind, ev.src_ip, ev.dst_port), ("syn", "192.168.1.77", 3306))

    def test_synack_and_other_hosts_ignored(self):
        self.assertIsNone(frame_to_event(tcp_syn("192.168.1.77", "192.168.1.70", 22, 0x12),
                                         "192.168.1.70", 1.0))
        self.assertIsNone(frame_to_event(tcp_syn("192.168.1.77", "192.168.1.60", 22),
                                         "192.168.1.70", 1.0))


class DetectorTests(unittest.TestCase):
    def test_single_touch_then_scan(self):
        d = Detector()
        a1 = d.handle(HoneypotEvent(0, "connect", "192.168.1.77", dst_port=23, service="Telnet",
                                    data="admin"))
        self.assertEqual(a1[0].title, "Connection to decoy Telnet")
        self.assertIn("admin", a1[0].detail)
        d.handle(HoneypotEvent(1, "connect", "192.168.1.77", dst_port=21, service="FTP"))
        a3 = d.handle(HoneypotEvent(2, "connect", "192.168.1.77", dst_port=3306, service="MySQL"))
        self.assertEqual(a3[0].title, "Port scan hit the honeypot")
        self.assertEqual(a3[0].ports, [21, 23, 3306])
        # More ports from the same scanner don't spam new alerts.
        self.assertEqual(d.handle(HoneypotEvent(3, "connect", "192.168.1.77", dst_port=5900,
                                                service="VNC")), [])

    def test_repeat_touch_is_quiet_then_rearms(self):
        d = Detector(quiet=600)
        ev = lambda t: HoneypotEvent(t, "connect", "10.0.0.5", dst_port=23, service="Telnet")  # noqa: E731
        self.assertEqual(len(d.handle(ev(0))), 1)
        self.assertEqual(d.handle(ev(5)), [])
        self.assertEqual(len(d.handle(ev(700))), 1)

    def test_syn_scan(self):
        d = Detector(own_ips={"192.168.1.70"})
        alerts = []
        for i, port in enumerate(range(20, 32)):
            alerts += d.handle(HoneypotEvent(i * 0.1, "syn", "192.168.1.77", dst_port=port))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].title, "Port scan detected")

    def test_normal_connections_not_a_scan(self):
        d = Detector()
        alerts = []
        for i in range(30):  # one client repeatedly using the Pi's real SSH
            alerts += d.handle(HoneypotEvent(i, "syn", "192.168.1.20", dst_port=22))
        self.assertEqual(alerts, [])

    def test_arp_sweep(self):
        d = Detector(own_macs={"aa:bb:cc:00:00:99"})
        alerts = []
        for i in range(1, 40):
            alerts += d.handle(HoneypotEvent(i * 0.05, "arp", "192.168.1.77",
                                             src_mac="aa:bb:cc:00:00:01", target_ip=f"192.168.1.{i}"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].title, "Network sweep detected")

    def test_own_sweeps_and_announcements_ignored(self):
        d = Detector(own_macs={"aa:bb:cc:00:00:99"})
        alerts = []
        for i in range(1, 40):
            alerts += d.handle(HoneypotEvent(i * 0.05, "arp", "192.168.1.70",
                                             src_mac="aa:bb:cc:00:00:99", target_ip=f"192.168.1.{i}"))
            alerts += d.handle(HoneypotEvent(i * 0.05, "arp", "192.168.1.8",
                                             src_mac="aa:bb:cc:00:00:08", target_ip="192.168.1.8"))
        self.assertEqual(alerts, [])

    def test_slow_arp_is_normal(self):
        d = Detector()
        alerts = []
        for i in range(1, 60):  # router refreshing one lease every few seconds
            alerts += d.handle(HoneypotEvent(i * 5, "arp", "192.168.1.1",
                                             src_mac="7c:a9:6b:12:34:56", target_ip=f"192.168.1.{i}"))
        self.assertEqual(alerts, [])


class StealthCounterTests(unittest.TestCase):
    """Windows can't see half-open scans directly; its TCP counters can."""

    def test_half_open_estimate(self):
        self.assertEqual(honeypot.half_open_from(12, 14), 12)  # nmap -sS
        self.assertEqual(honeypot.half_open_from(9, 0), 0)  # localhost apps talking
        self.assertEqual(honeypot.half_open_from(1, 0), 0)  # Noxis's scan (own fails removed)

    def test_burst_alerts_once(self):
        d = Detector()
        self.assertEqual(d.counters(0, 2, 2, 0), [])
        alerts = d.counters(5, 3, 3, 0)
        self.assertEqual([a.title for a in alerts], ["Stealth port scan detected"])
        self.assertEqual(alerts[0].src_ip, "")
        self.assertEqual(d.counters(8, 10, 10, 500), [])  # cooldown

    def test_own_scan_plus_localhost_is_quiet(self):
        """The false alarm seen live: localhost chatter while Noxis scans."""
        d = Detector()
        polls = [(t, 1 if t % 7 == 0 else 0, 0, 0) for t in range(60)]  # own fails subtracted
        polls[10] = (10, 1, 3, 0)   # kernel counted a failure a poll early...
        polls[11] = (11, 0, -3, 0)  # ...and Noxis noted it a poll later
        self.assertEqual([a for p in polls for a in d.counters(*p)], [])

    def test_slow_trickle_is_quiet(self):
        d = Detector()
        self.assertEqual([a for t in range(0, 300, 30) for a in d.counters(t, 1, 1, 10)], [])

    def test_closed_port_burst(self):
        self.assertEqual(Detector().counters(0, 0, 0, 1000)[0].title, "Port scan detected")

    def test_watcher_feeds_detector(self):
        readings = iter([(100, 50, 10), (100, 50, 10), (112, 64, 1011)])
        alerts = []
        hp = honeypot.Honeypot("192.168.1.20", None, alerts.append, ports=[])
        hp._read_counters = lambda: next(readings, (112, 64, 1011))
        hp._own_failed = lambda: 0
        hp._poll = 0.01
        stop = threading.Event()
        t = threading.Thread(target=hp._watch_counters, args=(stop,))
        t.start()
        time.sleep(0.2)
        stop.set()
        t.join()
        self.assertEqual([a.title for a in alerts], ["Stealth port scan detected"])



class LureTests(unittest.TestCase):
    def start(self, **kw):
        stop = threading.Event()
        hp = honeypot.Honeypot("127.0.0.1", None, lambda a: None, bind="127.0.0.1", **kw)
        hp._read_counters = lambda: None  # no stealth watcher in tests
        hp.start(stop)
        self.addCleanup(stop.set)
        return hp

    def test_off_by_default(self):
        self.assertNotIn(80, honeypot.Honeypot("127.0.0.1", None, lambda a: None).ports)

    def test_lure_adds_port_80(self):
        hp = honeypot.Honeypot("127.0.0.1", None, lambda a: None, ports=[2323], lure=True)
        self.assertEqual(hp.ports, [80, 2323])

    def test_single_lure_visit_is_medium_scan_is_high(self):
        d = Detector()
        first = d.handle(HoneypotEvent(0, "connect", "192.168.1.50", dst_port=80, service="web login page"))
        self.assertEqual((first[0].title, first[0].severity), ("Visit to the lure web login page", "medium"))
        d.handle(HoneypotEvent(1, "connect", "192.168.1.50", dst_port=23, service="Telnet"))
        scan = d.handle(HoneypotEvent(2, "connect", "192.168.1.50", dst_port=3306, service="MySQL"))
        self.assertEqual((scan[0].title, scan[0].severity), ("Port scan hit the honeypot", "high"))

    def test_lure_serves_login_page(self):
        hp = self.start(ports=[], lure=True)
        if 80 not in hp.listening:
            self.skipTest(f"port 80 unavailable here: {hp.skipped.get(80)}")
        with socket.create_connection(("127.0.0.1", 80), 3) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            body = s.recv(4096)
        self.assertTrue(body.startswith(b"HTTP/1.1 200 OK"))
        self.assertIn(b"type=password", body)


if __name__ == "__main__":
    unittest.main()
