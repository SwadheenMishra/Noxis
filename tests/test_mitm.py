import http.server
import threading
import unittest
from unittest import mock

from noxis import mitm


def tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + value


def name(cn: str, org: str) -> bytes:
    def attr(oid, val):
        return tlv(0x31, tlv(0x30, tlv(0x06, oid) + tlv(0x0C, val.encode())))
    return tlv(0x30, attr(b"\x55\x04\x0a", org) + attr(b"\x55\x04\x03", cn))


def fake_cert(issuer_org: str, issuer_cn: str = "Root", subject_cn: str = "www.google.com") -> bytes:
    """Structurally valid DER certificate (unsigned): enough for issuer parsing."""
    alg = tlv(0x30, tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b") + b"\x05\x00")
    tbs = tlv(0x30, tlv(0xA0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x01\x23") + alg
              + name(issuer_cn, issuer_org) + tlv(0x30, b"\x00" * 30)  # validity (padding)
              + name(subject_cn, "Subject Org") + tlv(0x30, b"\x00" * 200))  # long-form length
    return tlv(0x30, tbs + alg + tlv(0x03, b"\x00" + b"\x01" * 64))


class CertTests(unittest.TestCase):
    def test_parse_names(self):
        issuer, subject = mitm.cert_names(fake_cert("Google Trust Services", "WR2"))
        self.assertEqual(issuer, {"O": "Google Trust Services", "CN": "WR2"})
        self.assertEqual(subject["CN"], "www.google.com")

    def test_classify(self):
        self.assertEqual(mitm.classify_issuer({"O": "Let's Encrypt", "CN": "R11"})[0], "ok")
        self.assertEqual(mitm.classify_issuer({"O": "AVAST Software s.r.o.", "CN": "avast! Web/Mail Shield Root"})[:3],
                         ("intercepted", "Avast/AVG antivirus web shield", "medium"))
        self.assertEqual(mitm.classify_issuer({"O": "mitmproxy", "CN": "mitmproxy"})[2], "high")
        self.assertEqual(mitm.classify_issuer({"O": "Totally Legit Root", "CN": "X"})[0], "unknown")


def run_https(certs: dict):
    """check_https with _fetch_cert replaced: certs = {site: (der, verify_error)}."""
    with mock.patch.object(mitm, "_fetch_cert", side_effect=lambda s: certs[s]):
        return mitm.check_https(list(certs))


class HttpsTests(unittest.TestCase):
    def test_all_clean(self):
        checks, findings = run_https({"a.com": (fake_cert("DigiCert Inc"), None),
                                      "b.com": (fake_cert("Google Trust Services"), None)})
        self.assertEqual((checks[0].status, findings), ("ok", []))

    def test_antivirus_interception_is_named_once(self):
        av = fake_cert("AVAST Software s.r.o.", "avast! Web/Mail Shield Root")
        checks, findings = run_https({"a.com": (av, None), "b.com": (av, None)})
        self.assertEqual(checks[0].status, "fail")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")
        self.assertIn("Avast", findings[0].title)

    def test_mitmproxy_is_high(self):
        _, findings = run_https({"a.com": (fake_cert("mitmproxy", "mitmproxy"), None)})
        self.assertEqual(findings[0].severity, "high")

    def test_injected_root_is_high(self):
        _, findings = run_https({"a.com": (fake_cert("Free VPN Root Authority"), None)})
        self.assertEqual(findings[0].title, "Unrecognised authority signed a.com")

    def test_untrusted_fake_certificate(self):
        _, findings = run_https({"a.com": (fake_cert("Evil"), "self-signed certificate")})
        self.assertEqual(findings[0].title, "Fake certificate for a.com")
        self.assertEqual(findings[0].severity, "high")

    def test_offline_is_skipped(self):
        with mock.patch.object(mitm, "_fetch_cert", side_effect=OSError("no route")):
            checks, findings = mitm.check_https(["a.com"])
        self.assertEqual((checks[0].status, findings), ("skip", []))


def resolver(table):
    return lambda name: table.get(name, [])


class DnsTests(unittest.TestCase):
    PUBLIC = {s: ["142.250.1.1"] for s in mitm.DNS_SITES}

    def test_clean(self):
        checks, findings = mitm.check_dns(["192.168.1.1"], "192.168.1.1", resolve=resolver(self.PUBLIC))
        self.assertEqual([c.status for c in checks], ["ok", "ok", "ok"])
        self.assertEqual(findings, [])

    def test_nxdomain_hijack(self):
        def res(name):
            return ["93.184.216.34"] if name.startswith("noxis-check-") else self.PUBLIC.get(name, [])
        _, findings = mitm.check_dns(["192.168.1.1"], "192.168.1.1", resolve=res)
        self.assertEqual(findings[0].title, "DNS answers for websites that don't exist")

    def test_paypal_to_local_box(self):
        table = dict(self.PUBLIC, **{"www.paypal.com": ["192.168.1.66"]})
        checks, findings = mitm.check_dns(["192.168.1.1"], "192.168.1.1", resolve=resolver(table))
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("paypal", findings[0].title)
        self.assertEqual(checks[-1].status, "fail")

    def test_dns_servers_labelled(self):
        checks, findings = mitm.check_dns(["192.168.1.66", "1.1.1.1", "100.100.100.100"], "192.168.1.1",
                                          resolve=resolver(self.PUBLIC))
        self.assertIn("Cloudflare", checks[0].detail)
        self.assertIn("Tailscale", checks[0].detail)
        self.assertEqual([f.title for f in findings], ["DNS goes through another device on the network"])

    def test_unspecified_dns_ignored(self):
        checks, findings = mitm.check_dns(["80.80.80.53", "8.8.8.8", "0.0.0.0"], "192.168.1.1",
                                          resolve=resolver(self.PUBLIC), reverse=lambda ip: "")
        self.assertNotIn("0.0.0.0", checks[0].detail)
        self.assertNotIn("DNS goes through another device on the network", [f.title for f in findings])

    def check(self, servers, trusted=None):
        names = {"80.80.80.53": "dns1.example-isp.net"}
        return mitm.check_dns(servers, "192.168.1.1", resolve=resolver(self.PUBLIC), trusted_dns=trusted,
                              reverse=lambda ip: names.get(ip, ""))

    def test_isp_server_named_and_low(self):
        checks, findings = self.check(["80.80.80.53", "8.8.8.8"])
        self.assertIn("dns1.example-isp.net", checks[0].detail)
        self.assertEqual([(f.severity, f.title) for f in findings], [("low", "Unrecognised DNS server")])

    def test_trusted_isp_server_is_quiet(self):
        checks, findings = self.check(["80.80.80.53", "8.8.8.8"], trusted=["80.80.80.53", "8.8.8.8"])
        self.assertEqual((checks[0].status, findings), ("ok", []))
        self.assertIn("dns1.example-isp.net, trusted", checks[0].detail)

    def test_changed_dns_is_medium(self):
        checks, findings = self.check(["185.228.168.10", "8.8.8.8"], trusted=["80.80.80.53", "8.8.8.8"])
        self.assertEqual([(f.severity, f.title) for f in findings], [("medium", "DNS server changed")])
        self.assertIn("80.80.80.53", findings[0].detail)
        self.assertEqual(checks[0].status, "warn")

    def test_switching_to_known_resolver_is_fine(self):
        _, findings = self.check(["1.1.1.1"], trusted=["80.80.80.53"])
        self.assertEqual(findings, [])

    def test_trusted_pihole_is_fine(self):
        _, findings = mitm.check_dns(["192.168.1.70"], "192.168.1.1", known_lan={"192.168.1.70": "pi5"},
                                     resolve=resolver(self.PUBLIC))
        self.assertEqual(findings, [])


class HttpTests(unittest.TestCase):
    def serve(self, body: bytes):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_port}/connecttest.txt"

    def test_unmodified(self):
        url = self.serve(b"Microsoft Connect Test")
        checks, findings = mitm.check_http(url, "Microsoft Connect Test")
        self.assertEqual((checks[0].status, findings), ("ok", []))

    def test_injected_page(self):
        url = self.serve(b"<html><script src=//ads.example/x.js></script>Microsoft Connect Test</html>")
        checks, findings = mitm.check_http(url, "Microsoft Connect Test")
        self.assertEqual(checks[0].status, "fail")
        self.assertEqual(findings[0].severity, "medium")


if __name__ == "__main__":
    unittest.main()
