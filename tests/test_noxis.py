import struct
import unittest

from noxis import discovery, probes, protocols, risk
from noxis.fingerprint import classify
from noxis.models import Device, NetworkInfo, ScanResult


def make(**kw) -> Device:
    d = Device(ip=kw.pop("ip", "192.168.1.50"), **kw)
    classify(d)
    risk.assess_device(d, baseline_exists=kw.get("trusted", False))
    return d


class ClassifyTests(unittest.TestCase):
    def test_onvif_camera_is_high_risk(self):
        d = make(mac="44:19:b6:11:22:33", vendor="Hikvision", open_ports=[80, 554],
                 onvif={"name": "IPC", "hardware": "DS-2CD2043"})
        self.assertEqual(d.device_type, "camera")
        self.assertEqual(d.confidence, "high")
        self.assertEqual(d.risk, "high")
        self.assertEqual(d.model, "DS-2CD2043")

    def test_cheap_camera_from_http_and_ports(self):
        d = make(open_ports=[80, 34567],
                 banners={80: {"kind": "http", "server": "uc-httpd 1.0.0", "title": "NETSurveillance WEB"}})
        self.assertEqual(d.device_type, "camera")
        self.assertEqual(d.risk, "high")

    def test_espressif_board_is_medium_risk(self):
        d = make(mac="a0:dd:6c:00:00:02", vendor="Espressif")
        self.assertEqual(d.device_type, "microcontroller")
        self.assertEqual(d.risk, "medium")

    def test_esp32_cam_is_camera_not_microcontroller(self):
        d = make(mac="24:0a:c4:00:00:01", vendor="Espressif", open_ports=[80],
                 banners={80: {"kind": "http", "title": "ESP32-CAM Webserver"}})
        self.assertEqual(d.device_type, "camera")

    def test_iphone_from_sync_port_and_private_mac(self):
        d = make(mac="02:12:34:56:78:9a", randomized_mac=True, open_ports=[49152, 62078])
        self.assertEqual(d.device_type, "phone_apple")
        self.assertNotIn(d.risk, ("high", "medium"))

    def test_raspberry_pi(self):
        d = make(mac="b8:27:eb:01:02:03", vendor="Raspberry Pi", open_ports=[22],
                 banners={22: {"kind": "ssh", "banner": "SSH-2.0-OpenSSH_7.9p1 Raspbian-10"}})
        self.assertEqual(d.device_type, "sbc")
        self.assertEqual(d.risk, "medium")

    def test_raspberry_pi_5_by_vendor_and_name(self):
        d = make(mac="88:a2:9e:00:00:01", vendor="Raspberry Pi (Trading) Ltd",
                 hostnames=["pi5"], mdns_services=["_workstation._tcp"])
        self.assertEqual(d.device_type, "sbc")
        self.assertEqual(d.confidence, "high")

    def test_wifi_pineapple(self):
        d = make(open_ports=[1471], banners={})
        self.assertEqual(d.device_type, "attack_tool")
        self.assertEqual(d.risk, "high")

    def test_trusted_device_type_findings_suppressed_but_telnet_kept(self):
        d = Device(ip="192.168.1.60", mac="24:0a:c4:00:00:02", vendor="Espressif",
                   open_ports=[23], trusted=True)
        classify(d)
        risk.assess_device(d, baseline_exists=True)
        titles = [f.title for f in d.findings]
        self.assertNotIn("Unidentified microcontroller board", titles)
        self.assertIn("Telnet is open", titles)

    def test_untrusted_device_flagged_when_baseline_exists(self):
        d = Device(ip="192.168.1.61", mac="3c:0a:f3:00:00:01", netbios_name="DESKTOP-ABC")
        classify(d)
        risk.assess_device(d, baseline_exists=True)
        self.assertEqual(d.device_type, "computer_windows")
        self.assertIn("Not in your trusted devices", [f.title for f in d.findings])

    def test_unknown_device(self):
        d = make(mac="3c:0a:f3:00:00:09")
        self.assertEqual(d.device_type, "unknown")
        self.assertEqual(d.risk, "low")


class NetworkFindingTests(unittest.TestCase):
    def _result(self, devices):
        net = NetworkInfo(local_ip="192.168.1.20", prefix=24, cidr="192.168.1.0/24",
                          gateway_ip="192.168.1.1", gateway_mac="7c:a9:6b:12:34:56")
        return ScanResult(network=net, devices=devices, started="now", oui_sources=["IEEE"],
                          baseline_exists=True)

    def test_arp_spoofing_of_gateway(self):
        devs = [Device(ip="192.168.1.1", mac="aa:bb:cc:00:00:01", is_gateway=True),
                Device(ip="192.168.1.77", mac="aa:bb:cc:00:00:01")]
        r = self._result(devs)
        r.network.gateway_mac = "aa:bb:cc:00:00:01"  # what this scan saw
        risk.assess_network(r, previous_gateway_mac="7c:a9:6b:12:34:56")
        sev = {f.title: f.severity for f in r.findings}
        self.assertEqual(sev["One device is answering for several IP addresses including the router"], "high")
        self.assertEqual(sev["The router's hardware address changed"], "high")

    def test_isolation_warning(self):
        r = self._result([Device(ip="192.168.1.1", is_gateway=True),
                          Device(ip="192.168.1.20", is_self=True)])
        risk.assess_network(r, None)
        self.assertTrue(any("hidden" in f.title for f in r.findings))


class ParserTests(unittest.TestCase):
    def test_arp_windows_linux_macos(self):
        text = """
Interface: 192.168.1.20 --- 0x12
  192.168.1.1           7c-a9-6b-12-34-56     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
192.168.1.30 dev wlan0 lladdr 02:12:34:56:78:9a REACHABLE
192.168.1.77 dev wlan0  FAILED
? (192.168.1.45) at a0:dd:6c:00:00:02 on en0 ifscope [ethernet]
? (192.168.1.40) at 0:1b:2:3:4:5 on en0
"""
        t = discovery.parse_arp_output(text)
        self.assertEqual(t, {
            "192.168.1.1": "7c:a9:6b:12:34:56",
            "192.168.1.30": "02:12:34:56:78:9a",
            "192.168.1.45": "a0:dd:6c:00:00:02",
            "192.168.1.40": "00:1b:02:03:04:05",
        })

    def test_dns_roundtrip_with_compression(self):
        # Response: PTR _googlecast._tcp.local -> "Living Room._googlecast._tcp.local"
        name = protocols.encode_name("_googlecast._tcp.local")
        header = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0)
        rdata = bytes([11]) + b"Living Room" + b"\xc0\x0c"  # pointer to offset 12
        rr = name + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
        recs = protocols.parse_dns(header + rr)
        self.assertEqual(recs[0]["target"], "Living Room._googlecast._tcp.local")

    def test_netbios_status_parse(self):
        names = b""
        names += b"DESKTOP-ABC    " + b"\x00" + b"\x04\x00"
        names += b"WORKGROUP      " + b"\x00" + b"\x84\x00"
        data = b"\x00" * 12 + b"\x20" + b"CK" + b"A" * 30 + b"\x00" + b"\x00" * 10 + bytes([2]) + names
        self.assertEqual(discovery.parse_nbstat(data), ("DESKTOP-ABC", "WORKGROUP"))

    def test_http_parse(self):
        raw = (b"HTTP/1.1 401 Unauthorized\r\nServer: Boa/0.94\r\n"
               b'WWW-Authenticate: Basic realm="IPCamera Login"\r\n\r\n<title> Web </title>')
        info = probes.parse_http(raw)
        self.assertEqual(info["server"], "Boa/0.94")
        self.assertEqual(info["realm"], "IPCamera Login")
        self.assertEqual(info["title"], "Web")

    def test_wsd_onvif_parse(self):
        body = ("<d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>"
                "<d:Scopes>onvif://www.onvif.org/name/IPC%20Cam onvif://www.onvif.org/hardware/C6N"
                "</d:Scopes><d:XAddrs>http://192.168.1.50/onvif/device_service</d:XAddrs></d:ProbeMatch>")
        info = protocols.parse_wsd(body)
        self.assertEqual(info["onvif"], {"name": "IPC Cam", "hardware": "C6N"})

    def test_telnet_banner_cleanup(self):
        self.assertEqual(probes.clean_banner(b"\xff\xfd\x18\xff\xfb\x01(none) login: "), "(none) login:")


class TableTests(unittest.TestCase):
    def test_short_vendor(self):
        from noxis.report import short_vendor
        cases = {
            "Raspberry Pi (Trading) Ltd": "Raspberry Pi",
            "Syrotech Networks. Ltd.": "Syrotech Networks",
            "CLOUD NETWORK TECHNOLOGY SINGAPORE PTE. LTD.": "Cloud Network Technology Singapore",
            "Espressif Inc.": "Espressif",
            "Samsung Electronics Co.,Ltd": "Samsung Electronics",
            "TP-LINK TECHNOLOGIES CO.,LTD.": "TP-LINK Technologies",
            "AVM GmbH": "AVM",
        }
        for raw, short in cases.items():
            self.assertEqual(short_vendor(raw), short, raw)

    def test_columns_fit_terminal(self):
        from noxis.report import table_widths
        rows = [["Raspberry Pi", "Single-board computer (Raspberry Pi etc.)", "pi5"],
                ["Cloud Network Technology Singapore", "Windows computer", "This computer"]]
        full_rows, full = table_widths(rows, [5, 12, 17, 5], 1000, [10, 14, 8])
        self.assertEqual(full, [34, 41, 13])  # nothing cut when there's room
        fit_rows, fit = table_widths(rows, [5, 12, 17, 5], 100, [10, 14, 8])
        self.assertEqual(fit_rows[0][1], "Single-board computer")  # detail dropped first
        self.assertLessEqual(sum([5, 12, 17, 5]) + sum(fit) + 6, 100)

    def test_table_row_not_cut_when_wide(self):
        import io
        from noxis import report
        d = Device(ip="192.168.1.70", mac="88:a2:9e:00:00:01", vendor="Raspberry Pi (Trading) Ltd",
                   known_name="pi5")
        classify(d)
        net = NetworkInfo(local_ip="192.168.1.20", prefix=24, cidr="192.168.1.0/24", gateway_ip="192.168.1.1")
        buf = io.StringIO()
        report.print_report(ScanResult(network=net, devices=[d], started="x"), None, term=report.Term(buf))
        row = next(line for line in buf.getvalue().splitlines() if "192.168.1.70" in line)
        self.assertIn("Raspberry Pi ", row)
        self.assertIn(d.type_label, row)
        self.assertNotIn("~", row)


if __name__ == "__main__":
    unittest.main()
