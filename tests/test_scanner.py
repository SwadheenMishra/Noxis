"""Run the whole scan pipeline against a fake network.

Unit tests of the pieces didn't catch a scan that crashed on every run, so
this executes every line of `run_scan` with the network calls faked out.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from noxis import discovery, mitm, probes, protocols, scanner, upnp, wifi
from noxis.models import NetworkInfo
from noxis.oui import OuiDB

NET = NetworkInfo(local_ip="192.168.77.2", prefix=29, cidr="192.168.77.0/29",
                  gateway_ip="192.168.77.1", local_mac="3c:0a:f3:00:00:01", ssid="TestNet")
ARP = {"192.168.77.1": "7c:a9:6b:12:34:56", "192.168.77.4": "a0:dd:6c:00:00:02"}


async def fake_ping(ip, timeout_ms, sem):
    return 64 if ip in ARP else None


async def fake_sendarp(hosts):
    return {ip: mac for ip, mac in ARP.items() if ip in hosts}


async def fake_scan_ports(ips, ports, **kw):
    return {"192.168.77.1": [53, 80], "192.168.77.4": [80]}


async def fake_banners(open_ports):
    return {"192.168.77.4": {80: {"kind": "http", "title": "ESP32 Web Server"}}}


async def fake_rdns(ips):
    return {}


async def fake_tcp_state(*a, **k):
    return None


class ScanHarness(unittest.TestCase):
    """Runs run_scan against the fake network (no tests of its own)."""

    def run_scan(self, forwards=None, deep=None, extra=()):
        forwards = forwards or upnp.UpnpInfo()
        patches = [
            mock.patch.object(scanner, "get_network_info", return_value=NET),
            mock.patch.object(discovery, "ping", fake_ping),
            mock.patch.object(discovery, "sendarp_sweep", fake_sendarp),
            mock.patch.object(discovery, "tcp_state", fake_tcp_state),
            mock.patch.object(discovery, "read_arp_table", side_effect=lambda: dict(ARP)),
            mock.patch.object(discovery, "netbios_names", return_value={}),
            mock.patch.object(discovery, "reverse_dns", fake_rdns),
            mock.patch.object(protocols, "mdns_discover", return_value={}),
            mock.patch.object(protocols, "ssdp_discover", return_value={}),
            mock.patch.object(protocols, "wsd_discover", return_value={}),
            mock.patch.object(protocols, "fetch_upnp_descriptions", return_value={}),
            mock.patch.object(probes, "scan_ports", fake_scan_ports),
            mock.patch.object(probes, "grab_banners", fake_banners),
            mock.patch.object(wifi, "scan_nearby", return_value=[]),
            mock.patch.object(wifi, "connected_bssid", return_value=None),
            mock.patch.object(mitm, "run_checks", return_value=([], [])),
            mock.patch.object(upnp, "read_port_forwards", return_value=forwards),
            *(mock.patch.object(*e) for e in extra),  # (module, name, replacement)
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return scanner.run_scan(OuiDB(Path(tmp.name)), deep=deep)


class FullScanTests(ScanHarness):
    def test_scan_completes(self):
        r = self.run_scan()
        by_ip = {d.ip: d for d in r.devices}
        self.assertEqual(sorted(by_ip), ["192.168.77.1", "192.168.77.2", "192.168.77.4"])
        self.assertTrue(by_ip["192.168.77.1"].is_gateway)
        self.assertEqual(by_ip["192.168.77.4"].device_type, "microcontroller")
        self.assertEqual(r.upnp.status, "none")

    def test_port_forwards_reach_result(self):
        info = upnp.UpnpInfo(status="ok", mappings=[upnp.PortMapping("TCP", 2323, "192.168.77.4", 23)])
        r = self.run_scan(info)
        self.assertEqual(r.upnp.mappings[0].internal_client, "192.168.77.4")



class DeepOnceTests(ScanHarness):
    """Each device is deep-scanned once per run: in round 1, or when it first appears."""

    def test_rounds(self):
        deep_calls, port_calls = [], []

        async def fake_deep(ips, **kw):
            deep_calls.append(sorted(ips))
            return {ip: [80, 47123] if ip == "192.168.77.4" else [53, 80] for ip in ips}

        async def fake_ports(ips, ports, **kw):
            port_calls.append((sorted(ips), sorted(ports)))
            if ports == [47123]:
                return {ip: [47123] for ip in ips}
            return {ip: [53, 80] if ip == "192.168.77.1" else [80] for ip in ips}

        extra = [(probes, "deep_scan", fake_deep), (probes, "scan_ports", fake_ports)]
        tracker = scanner.DeepOnce()
        r1 = self.run_scan(deep=tracker, extra=extra)
        self.assertEqual(deep_calls, [["192.168.77.1", "192.168.77.4"]])
        self.assertIn(47123, next(d for d in r1.devices if d.ip == "192.168.77.4").open_ports)

        ARP["192.168.77.5"] = "02:11:22:33:44:55"  # a sleepy device wakes up
        self.addCleanup(ARP.pop, "192.168.77.5")
        r2 = self.run_scan(deep=tracker, extra=extra)
        self.assertEqual(deep_calls[1], ["192.168.77.5"])  # only the newcomer
        self.assertIn((["192.168.77.4"], [47123]), port_calls)  # deep-found port re-checked
        self.assertIn(47123, next(d for d in r2.devices if d.ip == "192.168.77.4").open_ports)

        self.run_scan(deep=tracker, extra=extra)
        self.assertEqual(len(deep_calls), 2)  # nothing new: no deep scan at all

    def test_mac_learned_after_deep_scan(self):
        """Seen live: the Pi's MAC arrived after its deep scan began, so round 2
        didn't recognise it and deep-scanned it again."""
        from noxis.models import Device
        t = scanner.DeepOnce()
        self.assertEqual(len(t.pick([Device(ip="192.168.1.70")])), 1)  # MAC not known yet
        t.remember(Device(ip="192.168.1.70"), {111})
        t.learn([Device(ip="192.168.1.70", mac="88:a2:9e:00:00:01")])
        pi = Device(ip="192.168.1.70", mac="88:a2:9e:00:00:01")
        self.assertEqual(t.pick([pi]), [])  # round 2: same device, no second deep scan
        self.assertEqual(t.extra_for(pi), {111})
        # A different device that took over the IP is new.
        self.assertEqual(len(t.pick([Device(ip="192.168.1.70", mac="02:00:00:00:00:01")])), 1)

    def test_connections_reach_deep_scan(self):
        seen = []

        async def fake_deep(ips, **kw):
            seen.append(kw["per_host"])
            return {}

        self.run_scan(deep=scanner.DeepOnce(connections=50), extra=[(probes, "deep_scan", fake_deep)])
        self.assertEqual(seen, [50])

    def test_connections_flag(self):
        import contextlib
        import io

        from noxis.__main__ import _deep, build_parser, main
        args = build_parser().parse_args(["sweep", "--deep", "--deep-connections", "100"])
        self.assertEqual(_deep(args).connections, 100)
        self.assertEqual(_deep(build_parser().parse_args(["scan", "--deep"])).connections, 200)
        for bad in (["scan", "--deep", "--deep-connections", "201"],
                    ["scan", "--deep", "--deep-connections", "0"],
                    ["scan", "--deep-connections", "100"]):  # without --deep
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                main(bad)

    def test_only_listed_devices(self):
        calls = []

        async def fake_deep(ips, **kw):
            calls.append(sorted(ips))
            return {}

        self.run_scan(deep=scanner.DeepOnce(["192.168.77.4"]),
                      extra=[(probes, "deep_scan", fake_deep)])
        self.assertEqual(calls, [["192.168.77.4"]])


if __name__ == "__main__":
    unittest.main()
