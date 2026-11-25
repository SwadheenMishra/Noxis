"""Branding: the owl banner in the terminal and the logo in HTML reports."""

import io
import os
import unittest
from unittest import mock

from noxis import __version__, report
from noxis.models import Device, Finding, NetworkInfo, ScanResult

NET = NetworkInfo(local_ip="192.168.1.20", prefix=24, cidr="192.168.1.0/24",
                  gateway_ip="192.168.1.1", ssid="HomeNet-5G")


class Utf8(io.StringIO):
    encoding = "utf-8"


class BannerTests(unittest.TestCase):
    def banner(self, env=None, **kw):
        out = Utf8()
        with mock.patch.dict(os.environ, env or {}):
            report.banner(report.Term(out), "watching", **kw)
        return out.getvalue()

    def test_owl_with_version_and_status(self):
        text = self.banner()
        self.assertIn("(•) (•)", text)
        self.assertNotIn("◉", text)  # off-centre in most terminal fonts
        self.assertIn(f"noxis {__version__}", text)
        self.assertIn("watching", text)
        self.assertIn(report.TAGLINE, text)

    def test_ascii_fallback(self):
        text = self.banner({"NOXIS_ASCII": "1"})
        self.assertIn("(o) (o)", text)
        self.assertNotIn("•", text)

    def test_no_colour_codes_in_a_pipe_or_log(self):
        self.assertNotIn("\033[", self.banner())

    def test_alert_eyes_are_amber(self):
        t = report.Term(Utf8())
        t.color = True
        self.assertIn(report._COLORS["alert"], report.alert_mark(t))


class ReportBrandTests(unittest.TestCase):
    def render(self, findings=()):
        d = Device(ip="192.168.1.45", mac="a0:dd:6c:00:00:02", findings=list(findings))
        return report.render_html(ScanResult(network=NET, devices=[d], started="2026-11-25T12:00:00"))

    def test_logo_and_all_clear(self):
        page = self.render()
        header = page.split("<main>")[0]
        self.assertIn("aria-label='Ward, the Noxis owl'", header)  # the full owl up top
        self.assertNotIn(f"stroke='{report.BRAND['alert']}'", header)  # no alarm marks
        self.assertIn("All clear", page)
        self.assertIn(report.BRAND["radar"], page)
        self.assertIn("rel='icon'", page)

    def test_needs_a_look_turns_the_eyes_amber(self):
        page = self.render([Finding("high", "Camera on the network")])
        self.assertIn("Needs a look", page)
        self.assertIn(f"stroke='{report.BRAND['alert']}'", page.split("<main>")[0])  # alarm marks
        self.assertIn(f"fill='{report.BRAND['alert']}'", page.split("<main>")[0].split("</style>")[1])

    def test_report_works_offline(self):
        page = self.render()
        self.assertNotIn("http://", page.replace("http://www.w3.org/2000/svg", ""))
        self.assertNotIn("https://", page)


if __name__ == "__main__":
    unittest.main()
