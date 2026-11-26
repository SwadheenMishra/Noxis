"""Nearby Wi-Fi, trusted-device fingerprints and sweep merging."""

import unittest

from noxis import risk, wifi
from noxis.fingerprint import classify
from noxis.models import Device, NetworkInfo, ScanResult
from noxis.scanner import merge_rounds

NETSH = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : HomeNet-5G
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 7c:a9:6b:12:34:57
         Signal             : 88%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 44
    BSSID 2                 : 12:34:56:78:9a:bc
         Signal             : 40%
         Channel            : 6

SSID 2 : HDWiFiCam-8812
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : a0:dd:6c:11:22:33
         Signal             : 92%
         Band               : 2.4 GHz
         Channel            : 1

SSID 3 :
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 9c:8e:cd:01:02:03
         Signal             : 75%
"""


def titles(items):
    return [f.title for f in items]


class WifiTests(unittest.TestCase):
    def setUp(self):
        self.aps = wifi.parse_netsh_networks(NETSH)
        vendors = {"a0:dd:6c:11:22:33": "Espressif Inc.", "9c:8e:cd:01:02:03": "Amcrest Technologies"}
        for ap in self.aps:
            ap.vendor = vendors.get(ap.bssid)

    def test_parse(self):
        self.assertEqual([a.ssid for a in self.aps], ["HomeNet-5G", "HomeNet-5G", "HDWiFiCam-8812", ""])
        first = self.aps[0]
        self.assertEqual((first.signal, first.band, first.channel, first.auth),
                         (88, "5 GHz", "44", "WPA2-Personal"))
        self.assertTrue(self.aps[2].is_open)

    def test_camera_hotspots_flagged(self):
        wifi.assess_nearby(self.aps, "HomeNet-5G", "7c:a9:6b:12:34:57", [])
        cam, hidden = self.aps[2], self.aps[3]
        self.assertIn("Camera-style Wi-Fi hotspot nearby", titles(cam.findings))
        # Hidden network from a camera maker (Amcrest) is flagged by vendor.
        self.assertIn("Camera-style Wi-Fi hotspot nearby", titles(hidden.findings))
        self.assertIn("Strong hidden network nearby", titles(hidden.findings))

    def test_router_bands_not_evil_twin(self):
        ap = wifi.AccessPoint(ssid="HomeNet-5G", bssid="7e:a9:6b:12:34:56", auth="WPA2-Personal")
        wifi.assess_nearby([self.aps[0], ap], "HomeNet-5G", "7c:a9:6b:12:34:57", [])
        self.assertEqual(ap.findings, [])

    def test_open_evil_twin_is_high(self):
        twin = wifi.AccessPoint(ssid="HomeNet-5G", bssid="00:c0:ca:aa:bb:cc", auth="Open")
        wifi.assess_nearby([self.aps[0], twin], "HomeNet-5G", "7c:a9:6b:12:34:57", [])
        self.assertEqual(twin.findings[0].severity, "high")

    def test_unknown_ap_after_trust_is_flagged(self):
        net = wifi.assess_nearby(self.aps, "HomeNet-5G", "7c:a9:6b:12:34:57", ["7c:a9:6b:12:34:57"])
        self.assertIn("New access point using your network's name", titles(self.aps[1].findings))
        self.assertEqual(net, [])

    def test_connected_to_untrusted_ap(self):
        net = wifi.assess_nearby(self.aps, "HomeNet-5G", "12:34:56:78:9a:bc", ["7c:a9:6b:12:34:57"])
        self.assertEqual(net[0].severity, "high")

    def test_phone_hotspot_rotating_bssid_is_not_evil_twin(self):
        ap = wifi.AccessPoint(ssid="My Phone", bssid="26:00:00:00:00:01", auth="WPA3-Personal")
        net = wifi.assess_nearby([ap], "My Phone", "26:00:00:00:00:01", ["c2:00:00:00:00:02"])
        self.assertEqual([f.severity for f in net], ["info"])

    def test_nmcli_parse(self):
        aps = wifi.parse_nmcli("IPC-1234:AA\\:BB\\:CC\\:DD\\:EE\\:FF:80:6:\n")
        self.assertEqual((aps[0].ssid, aps[0].bssid, aps[0].auth), ("IPC-1234", "aa:bb:cc:dd:ee:ff", "Open"))


class WifiRescanTests(unittest.TestCase):
    """nmcli returns an old list when a fresh scan isn't allowed: say so."""

    PERMS = ("org.freedesktop.NetworkManager.network-control:yes\n"
             "org.freedesktop.NetworkManager.wifi.scan:{v}\n")

    def allowed(self, value, root=False):
        from unittest import mock
        with mock.patch.object(wifi, "IS_WINDOWS", False), \
                mock.patch("os.geteuid", create=True, return_value=0 if root else 1000), \
                mock.patch.object(wifi, "run", return_value=self.PERMS.format(v=value)):
            return wifi.rescan_allowed()

    def test_permission(self):
        self.assertTrue(self.allowed("yes"))
        self.assertFalse(self.allowed("no"))
        self.assertFalse(self.allowed("auth"))  # would need a password prompt nobody sees
        self.assertTrue(self.allowed("no", root=True))

    def test_no_networkmanager_means_no_warning(self):
        from unittest import mock
        with mock.patch.object(wifi, "IS_WINDOWS", False), \
                mock.patch("os.geteuid", create=True, return_value=1000), \
                mock.patch.object(wifi, "run", return_value=""):
            self.assertTrue(wifi.rescan_allowed())

    def test_report_says_list_may_be_old(self):
        import io
        from noxis import report
        net = NetworkInfo(local_ip="192.168.1.70", prefix=24, gateway_ip="192.168.1.1", cidr="192.168.1.0/24",
                          ssid="HomeNet-5G")
        r = ScanResult(network=net, devices=[], started="2026-01-01T00:00:00", wifi_scanned=True,
                       wifi_stale=True)
        out = io.StringIO()
        report._nearby_lines(report.Term(out), r)
        self.assertIn("Possibly out of date", out.getvalue())
        self.assertIn("noxis service install", out.getvalue())
        self.assertIn("Possibly out of date", "".join(report._html_nearby(r)))
        r.wifi_stale = False
        self.assertNotIn("Possibly out of date", "".join(report._html_nearby(r)))

    def test_power_save_hint(self):
        from unittest import mock
        answers = {("iw", "dev"): "phy#0\n\tInterface wlan0\n\t\ttype managed\n",
                   ("iw", "dev", "wlan0", "get", "power_save"): "Power save: on\n",
                   ("nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"):
                       "HomeNet-5G:wlan0\nlo:lo\n"}
        with mock.patch.object(wifi, "IS_WINDOWS", False), \
                mock.patch.object(wifi, "run", side_effect=lambda cmd, **kw: answers.get(tuple(cmd), "")):
            hint = wifi.power_save_hint()
        self.assertIn("sudo iw dev wlan0 set power_save off", hint)
        self.assertIn('sudo nmcli connection modify "HomeNet-5G" 802-11-wireless.powersave 2', hint)
        answers[("iw", "dev", "wlan0", "get", "power_save")] = "Power save: off\n"
        with mock.patch.object(wifi, "IS_WINDOWS", False), \
                mock.patch.object(wifi, "run", side_effect=lambda cmd, **kw: answers.get(tuple(cmd), "")):
            self.assertIsNone(wifi.power_save_hint())


class TrustDnsTests(unittest.TestCase):
    def test_trust_all_saves_dns(self):
        import os
        import tempfile
        from unittest import mock

        from noxis.store import Store
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with mock.patch.dict(os.environ, {"NOXIS_HOME": tmp.name}):
            net = NetworkInfo(local_ip="192.168.1.20", prefix=24, cidr="192.168.1.0/24",
                              gateway_ip="192.168.1.1", ssid="HomeNet-5G",
                              dns=["80.80.80.53", "8.8.8.8", "0.0.0.0"])
            store = Store()
            store.record(ScanResult(network=net, devices=[], started="2026-11-24T12:00:00"))
            added = store.trust([], None, trust_all=True)
            self.assertIn("DNS server 80.80.80.53", added)
            self.assertEqual(Store().dns_context(net.network_id)[1], ["80.80.80.53", "8.8.8.8"])


class RenameMigrationTests(unittest.TestCase):
    """Noxis was called Warden: its data must carry over on first run."""

    def setUp(self):
        import os
        import tempfile
        from pathlib import Path
        from unittest import mock
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        env = {k: v for k, v in os.environ.items() if k not in ("NOXIS_HOME", "WARDEN_HOME")}
        for p in (mock.patch.dict(os.environ, env, clear=True),
                  mock.patch.object(Path, "home", return_value=self.home)):
            p.start()
            self.addCleanup(p.stop)

    def test_old_folder_is_copied_once(self):
        from noxis.store import data_dir
        old = self.home / ".warden"
        old.mkdir()
        (old / "networks.json").write_text('{"wifi:HomeNet-5G": {"known": {}}}', encoding="utf-8")
        new = data_dir()
        self.assertEqual(new, self.home / ".noxis")
        self.assertIn("HomeNet-5G", (new / "networks.json").read_text(encoding="utf-8"))
        self.assertTrue(old.is_dir())  # kept as a backup
        (old / "networks.json").write_text("{}", encoding="utf-8")
        data_dir()  # later runs don't copy again
        self.assertIn("HomeNet-5G", (new / "networks.json").read_text(encoding="utf-8"))

    def test_old_env_var_still_works(self):
        import os
        from noxis.store import data_dir
        os.environ["WARDEN_HOME"] = str(self.home / "custom")
        self.assertEqual(data_dir(), self.home / "custom")
        os.environ["NOXIS_HOME"] = str(self.home / "newer")
        self.assertEqual(data_dir(), self.home / "newer")  # the new name wins


class FingerprintTests(unittest.TestCase):
    def _trusted(self, **kw):
        d = Device(ip="192.168.1.45", mac="a0:dd:6c:00:00:02", vendor="Espressif", trusted=True,
                   trusted_profile={"type": "microcontroller", "ports": [], "vendor": "Espressif"}, **kw)
        classify(d)
        risk.assess_device(d, baseline_exists=True)
        return d

    def test_same_device_is_quiet(self):
        self.assertEqual(self._trusted().findings, [])

    def test_cloned_mac_running_camera(self):
        d = self._trusted(open_ports=[80, 554],
                          banners={554: {"kind": "rtsp", "status": "200 OK"}})
        t = titles(d.findings)
        self.assertIn("Trusted device now looks like a different device", t)
        self.assertIn("New service on a trusted device", t)
        self.assertEqual(d.risk, "high")

    def test_new_harmless_port_is_medium(self):
        d = self._trusted(open_ports=[80])
        self.assertEqual(d.risk, "medium")


class SweepMergeTests(unittest.TestCase):
    def test_merge_rounds(self):
        net = NetworkInfo(local_ip="192.168.1.20", prefix=24, cidr="192.168.1.0/24", gateway_ip="192.168.1.1")

        def result(devs, aps):
            return ScanResult(network=net, devices=devs, started="2026-11-23T10:00:00", nearby=aps,
                              wifi_scanned=True)

        r1 = result([Device(ip="192.168.1.30")],  # sleepy phone: MAC missed
                    [wifi.AccessPoint(ssid="X", bssid="aa:aa:aa:aa:aa:aa", signal=40)])
        r2 = result([Device(ip="192.168.1.30", mac="02:12:34:56:78:9a", randomized_mac=True,
                            open_ports=[62078]),
                     Device(ip="192.168.1.50", mac="44:19:b6:00:00:01", onvif={"name": "IPC"})],
                    [wifi.AccessPoint(ssid="X", bssid="aa:aa:aa:aa:aa:aa", signal=70)])
        m = merge_rounds([r1, r2])
        self.assertEqual(m.rounds, 2)
        by_ip = {d.ip: d for d in m.devices}
        self.assertEqual(len(m.devices), 2)
        self.assertEqual(by_ip["192.168.1.30"].seen_rounds, [1, 2])
        self.assertEqual(by_ip["192.168.1.30"].device_type, "phone_apple")
        self.assertEqual(by_ip["192.168.1.50"].seen_rounds, [2])
        self.assertEqual(by_ip["192.168.1.50"].device_type, "camera")
        self.assertEqual(m.nearby[0].signal, 70)
        self.assertEqual(m.nearby[0].seen_rounds, [1, 2])


if __name__ == "__main__":
    unittest.main()
