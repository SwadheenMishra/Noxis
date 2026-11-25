"""Reading network settings on Windows without PowerShell."""

import sys
import unittest
from unittest import mock

from noxis import netinfo

ADAPTERS = [
    {"iface": "Tailscale", "if_type": 53, "up": True, "mac": None,
     "addresses": [("100.64.0.10", 32)], "gateways": [], "dns": ["100.100.100.100"]},
    {"iface": "Wi-Fi", "if_type": 71, "up": True, "mac": "3C-0A-F3-00-00-01",
     "addresses": [("192.168.1.20", 24)], "gateways": ["192.168.1.1"],
     "dns": ["80.80.80.53", "8.8.8.8"]},
]
NETSH = "    Name                   : Wi-Fi\n    State                  : connected\n    SSID                   : HomeNet-5G\n"


class WindowsFastTests(unittest.TestCase):
    def test_picks_the_adapter_holding_our_address(self):
        with mock.patch.object(netinfo, "_adapters_windows", return_value=ADAPTERS), \
                mock.patch.object(netinfo, "run", return_value=NETSH):
            info = netinfo._windows_fast("192.168.1.20")
        self.assertEqual((info["iface"], info["prefix"], info["gateway"], info["ssid"]),
                         ("Wi-Fi", 24, "192.168.1.1", "HomeNet-5G"))
        self.assertEqual(info["dns"], ["80.80.80.53", "8.8.8.8"])  # not Tailscale's

    def test_hidden_ssid_falls_back_to_profile_name(self):
        def fake_run(args, timeout=None):
            if args[0] == "netsh":
                return "    Name   : Wi-Fi\n    State  : connected\n"  # no SSID without location access
            return "HomeNet-5G 2\r\n"  # Get-NetConnectionProfile

        with mock.patch.object(netinfo, "_adapters_windows", return_value=ADAPTERS), \
                mock.patch.object(netinfo, "run", side_effect=fake_run):
            self.assertEqual(netinfo._windows_fast("192.168.1.20")["ssid"], "HomeNet-5G")

    def test_api_failure_falls_back_to_powershell(self):
        with mock.patch.object(netinfo, "_adapters_windows", side_effect=OSError("boom")), \
                mock.patch.object(netinfo, "_windows_powershell", return_value={"prefix": 24}) as slow:
            self.assertEqual(netinfo._windows("192.168.1.20"), {"prefix": 24})
        slow.assert_called_once()

    def test_unknown_address_falls_back_to_powershell(self):
        with mock.patch.object(netinfo, "_adapters_windows", return_value=ADAPTERS), \
                mock.patch.object(netinfo, "_windows_powershell", return_value={}) as slow:
            netinfo._windows("10.9.9.9")
        slow.assert_called_once()

    @unittest.skipUnless(sys.platform == "win32", "Windows API")
    def test_real_api_call(self):
        adapters = netinfo._adapters_windows()
        loopback = [a for a in adapters if ("127.0.0.1", 8) in a["addresses"]]
        self.assertTrue(loopback, adapters)


if __name__ == "__main__":
    unittest.main()
