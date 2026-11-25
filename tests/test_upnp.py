"""Router port forwards (UPnP IGD), tested against a fake router."""

import http.server
import re
import threading
import unittest
from unittest import mock

from noxis import upnp
from noxis.models import Device, NetworkInfo, ScanResult
from noxis.scanner import merge_rounds

SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:1"

DESCRIPTION = f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>Home Router</friendlyName><manufacturer>Acme</manufacturer>
  <modelName>AC-GPON-100</modelName>
  <deviceList><device><deviceList><device>
   <serviceList>
    <service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
     <controlURL>/ctl/CmnIfCfg</controlURL></service>
    <service><serviceType>{SERVICE}</serviceType><controlURL>/ctl/IPConn</controlURL></service>
   </serviceList>
  </device></deviceList></device></deviceList>
 </device>
</root>"""

FORWARDS = [  # (proto, ext, client, int, description)
    ("TCP", 8096, "192.168.1.70", 8096, "Jellyfin"),
    ("TCP", 23231, "192.168.1.77", 23, "miniupnpd"),
    ("UDP", 3074, "192.168.1.30", 3074, "Xbox"),
    ("TCP", 9000, "192.168.1.88", 9000, ""),
]


def entry_xml(i):
    proto, ext, client, port, desc = FORWARDS[i]
    return ("<s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse>"
            f"<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort>"
            f"<NewProtocol>{proto}</NewProtocol><NewInternalPort>{port}</NewInternalPort>"
            f"<NewInternalClient>{client}</NewInternalClient><NewEnabled>1</NewEnabled>"
            f"<NewPortMappingDescription>{desc}</NewPortMappingDescription>"
            "<NewLeaseDuration>0</NewLeaseDuration>"
            "</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>")


FAULT = ("<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>713</errorCode>"
         "<errorDescription>SpecifiedArrayIndexInvalid</errorDescription>"
         "</UPnPError></detail></s:Fault></s:Body></s:Envelope>")


class FakeRouter(http.server.BaseHTTPRequestHandler):
    external_ip = "49.36.10.20"
    actions: list = []

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(200, DESCRIPTION) if self.path == "/desc.xml" else self._send(404, "")

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        action = self.headers["SOAPAction"].strip('"').split("#")[1]
        FakeRouter.actions.append(action)
        if self.path != "/ctl/IPConn":
            return self._send(404, "")
        if action == "GetExternalIPAddress":
            return self._send(200, f"<NewExternalIPAddress>{self.external_ip}</NewExternalIPAddress>")
        if action == "GetGenericPortMappingEntry":
            i = int(re.search(r"<NewPortMappingIndex>(\d+)<", body).group(1))
            return self._send(200, entry_xml(i)) if i < len(FORWARDS) else self._send(500, FAULT)
        self._send(500, FAULT)


class RouterTestCase(unittest.TestCase):
    def setUp(self):
        FakeRouter.actions = []
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeRouter)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.location = f"http://127.0.0.1:{srv.server_port}/desc.xml"

    def read(self):
        with mock.patch.object(upnp, "find_gateway_services", return_value=[self.location]), \
                mock.patch.object(upnp, "natpmp_answers", return_value=False):
            return upnp.read_port_forwards("192.168.1.20", "127.0.0.1")


class ReadTests(RouterTestCase):
    def test_reads_every_forward_then_stops(self):
        info = self.read()
        self.assertEqual(info.status, "ok")
        self.assertEqual(info.router, "Acme AC-GPON-100")
        self.assertEqual(info.external_ip, "49.36.10.20")
        self.assertEqual([(m.external_port, m.internal_client) for m in info.mappings],
                         [(8096, "192.168.1.70"), (23231, "192.168.1.77"),
                          (3074, "192.168.1.30"), (9000, "192.168.1.88")])
        self.assertEqual(info.mappings[0].description, "Jellyfin")

    def test_read_only(self):
        self.read()
        self.assertEqual(set(FakeRouter.actions), {"GetExternalIPAddress", "GetGenericPortMappingEntry"})

    def test_control_url_must_stay_on_router(self):
        xml = DESCRIPTION.replace("<controlURL>/ctl/IPConn</controlURL>",
                                  "<controlURL>http://203.0.113.9/steal</controlURL>")
        self.assertEqual(upnp.parse_description(xml, self.location)[2], "")

    def test_no_upnp(self):
        with mock.patch.object(upnp, "find_gateway_services", return_value=[]), \
                mock.patch.object(upnp, "natpmp_answers", return_value=False):
            info = upnp.read_port_forwards("192.168.1.20", "192.168.1.1")
        self.assertEqual(info.status, "none")
        check, net, per = upnp.assess(info, [])
        self.assertEqual((check.status, net, per), ("ok", [], {}))
        self.assertIn("doesn't offer UPnP", check.detail)


def devices():
    pi = Device(ip="192.168.1.70", mac="88:a2:9e:00:00:01", device_type="sbc",
                type_label="Single-board computer", trusted=True, known_name="pi5")
    esp = Device(ip="192.168.1.77", mac="a0:dd:6c:00:00:01", device_type="microcontroller",
                 type_label="Microcontroller (ESP32/ESP8266)")
    phone = Device(ip="192.168.1.30", mac="02:12:34:56:78:9a", device_type="phone_apple",
                   type_label="iPhone / iPad")
    return [pi, esp, phone]


class AssessTests(RouterTestCase):
    def test_severities(self):
        check, net, per = upnp.assess(self.read(), devices())
        sev = lambda fs: [(f.severity, f.title) for f in fs]  # noqa: E731
        self.assertEqual(sev(per["192.168.1.70"]), [("low", "Port open to the internet")])
        self.assertEqual(sev(per["192.168.1.77"]), [("high", "Telnet is exposed to the internet")])
        self.assertEqual(sev(per["192.168.1.30"]), [("medium", "Port open to the internet")])
        self.assertIn(("medium", "Port forwarded to a device Noxis can't see"), sev(net))
        self.assertEqual(net[0].title, "UPnP is on: any device can open ports on your router")
        self.assertEqual(check.status, "fail")
        self.assertIn("4 forward(s)", check.detail)

    def test_cgnat_lowers_severity(self):
        FakeRouter.external_ip = "100.64.0.5"
        self.addCleanup(setattr, FakeRouter, "external_ip", "49.36.10.20")
        info = self.read()
        self.assertTrue(info.cgnat)
        _, _, per = upnp.assess(info, devices())
        f = per["192.168.1.77"][0]
        self.assertEqual(f.severity, "medium")
        self.assertIn("CGNAT", f.detail)

    def test_without_device_scan(self):
        """`noxis check` has no device list: no 'can't see' claims."""
        _, net, per = upnp.assess(self.read(), None)
        self.assertEqual(per, {})
        self.assertNotIn("Port forwarded to a device Noxis can't see", [f.title for f in net])

    def test_merge_keeps_every_forward(self):
        net = NetworkInfo(local_ip="192.168.1.20", prefix=24, cidr="192.168.1.0/24",
                          gateway_ip="192.168.1.1")
        a = upnp.UpnpInfo(status="ok", mappings=[upnp.PortMapping("TCP", 8096, "192.168.1.70", 8096)])
        b = upnp.UpnpInfo(status="ok", mappings=[upnp.PortMapping("UDP", 3074, "192.168.1.30", 3074)])
        rounds = [ScanResult(network=net, devices=[], started="x", upnp=u) for u in (a, b)]
        merged = merge_rounds(rounds)
        self.assertEqual(sorted(m.external_port for m in merged.upnp.mappings), [3074, 8096])


if __name__ == "__main__":
    unittest.main()
