"""MAC address -> manufacturer lookup.

Sources, later ones win:
  1. A small built-in table of security-relevant makers (always available).
  2. nmap's `nmap-mac-prefixes` file, if nmap is installed.
  3. The official IEEE registry, downloaded by `noxis update-oui`.
"""

from __future__ import annotations

import csv
import io
import shutil
import urllib.request
from pathlib import Path

from .util import is_randomized_mac

_BUILTIN: dict[str, list[str]] = {
    "Espressif": [
        "3C71BF", "807D3A", "B4E62D", "ECFABC", "D8A01D", "240AC4", "545AA6", "500291",
        "A020A6", "2CF432", "840D8E", "84F3EB", "A47B9D", "2C3AE8", "600194", "9097D5",
        "18FE34", "A4CF12", "BCDDC2", "DC4F22", "C82B96", "4C11AE", "2462AB", "5CCF7F",
        "C44F33", "CC50E3", "68C63A", "24B2DE", "30AEA4", "ACD074", "246F28", "D8F15B",
        # newer assignments (not in older nmap releases)
        "A0DD6C", "7C9EBD", "94B97E", "AC67B2", "E8DB84", "483FDA", "349454", "10521C",
        "083AF2", "58BF25", "8CAAB5", "84CCA8", "C8C9A3", "98CDAC", "3C6105", "40F520",
        "782184", "34B472", "48E729", "F008D1", "DCDA0C", "64E833",
    ],
    "Raspberry Pi": ["B827EB", "DCA632", "E45F01", "28CDC1", "D83ADD", "2CCF67", "88A29E"],
    "Arduino": ["A8610A"],
    "Seeed Technology": ["2CF7F1"],
    "Hikvision": ["BCAD28", "F84DFC", "BCBAC2", "64DB8B", "988B0A", "5803FB", "4447CC",
                  "A41437", "686DBC", "4419B6", "C056E3", "2857BE", "54C415", "1868CB",
                  "C42F90", "B4A382", "94E1AC", "4CBD8F"],
    "Dahua": ["E0508B", "9002A9", "3CEF8C", "24526A", "4C11BF", "9C1463", "14A78B",
              "08EDED", "38AF29", "BC325F", "A0BD1D"],
    "Amcrest": ["9C8ECD"],
    "Reolink (Baichuan)": ["EC71DB"],
    "Wyze Labs": ["2CAA8E"],
    "Axis Communications": ["B8A44F", "00408C", "ACCC8E"],
    "Vivotek": ["0002D1"],
    "Arlo": ["A41162"],
    "Shenzhen Bilian (IoT Wi-Fi modules)": ["28F366", "3C3300", "20F41B", "ACA213", "44334C",
                                            "E0B94D", "0C8C24", "EC3DFD", "74EE2A", "08EA40",
                                            "10A4BE", "146B9C", "203233"],
    "Ubiquiti": ["F09FC2", "0418D6", "44D9E7", "E063DA", "802AA8", "00156D", "FCECDA",
                 "18E829", "24A43C", "788A20", "DC9FDB", "7483C2", "002722", "687251", "B4FBE4"],
    "Sonos": ["5CAAFD", "000E58", "48A6B8", "00043C", "542A1B", "949F3E", "B8E937",
              "7828CA", "347E5C"],
    "Roku": ["AC3A7A", "CC6DA0", "000D4B", "ACAE19", "B8A175", "8C4962", "D04D2C",
             "88DEA9", "080581", "B0A737", "B83E59", "DC3A5E", "B0EE7B", "C83A6B"],
    "Nest Labs": ["18B430", "641666"],
    "Philips Lighting (Hue)": ["ECB5FA", "001788"],
    "ecobee": ["446132"],
    "iRobot": ["501479"],
    "Synology": ["001132"],
    "QNAP": ["245EBE", "E843B6"],
    "Seiko Epson": ["A4EE57", "50579C", "0026AB", "64EB8C", "381A52", "F8D027", "44D244",
                    "9CAED3", "B0E892", "AC1826", "389D92"],
}

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def _nmap_file() -> Path | None:
    candidates = []
    exe = shutil.which("nmap")
    if exe:
        candidates.append(Path(exe).resolve().parent / "nmap-mac-prefixes")
    candidates += [
        Path(r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes"),
        Path(r"C:\Program Files\Nmap\nmap-mac-prefixes"),
        Path("/usr/share/nmap/nmap-mac-prefixes"),
        Path("/usr/local/share/nmap/nmap-mac-prefixes"),
        Path("/opt/homebrew/share/nmap/nmap-mac-prefixes"),
    ]
    return next((p for p in candidates if p.is_file()), None)


class OuiDB:
    def __init__(self, data_dir: Path):
        self.prefixes: dict[str, str] = {}
        self.sources: list[str] = ["built-in"]
        for vendor, prefixes in _BUILTIN.items():
            for p in prefixes:
                self.prefixes[p] = vendor

        nmap = _nmap_file()
        if nmap:
            count = 0
            for line in nmap.read_text(encoding="utf-8", errors="replace").splitlines():
                if len(line) > 7 and not line.startswith("#"):
                    prefix, _, vendor = line.partition(" ")
                    if len(prefix) == 6:
                        self.prefixes.setdefault(prefix.upper(), vendor.strip())
                        count += 1
            if count:
                self.sources.append("nmap")

        ieee = data_dir / "oui.tsv"
        if ieee.is_file():
            for line in ieee.read_text(encoding="utf-8").splitlines():
                prefix, _, vendor = line.partition("\t")
                if len(prefix) == 6 and vendor:
                    self.prefixes[prefix] = vendor  # authoritative: override
            self.sources.append("IEEE")

    @property
    def has_ieee(self) -> bool:
        return "IEEE" in self.sources

    def lookup(self, mac: str | None) -> str | None:
        if not mac or is_randomized_mac(mac):
            return None
        return self.prefixes.get(mac.replace(":", "")[:6].upper())


def update_from_ieee(data_dir: Path) -> int:
    """Download the IEEE MA-L registry and cache it as oui.tsv. Returns count."""
    req = urllib.request.Request(
        IEEE_URL, headers={"User-Agent": "Mozilla/5.0 (compatible; Noxis OUI updater)"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        text = resp.read().decode("utf-8", "replace")
    rows = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 3 and len(row[1]) == 6 and row[0].startswith("MA-"):
            rows.append(f"{row[1].upper()}\t{row[2].strip()}")
    if len(rows) < 1000:
        raise RuntimeError(f"IEEE download looked wrong ({len(rows)} rows); keeping old data")
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = data_dir / "oui.tsv.tmp"
    tmp.write_text("\n".join(rows), encoding="utf-8")
    tmp.replace(data_dir / "oui.tsv")
    return len(rows)
