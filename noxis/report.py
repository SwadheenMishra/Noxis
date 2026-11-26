"""Terminal and HTML output."""

from __future__ import annotations

import html
import os
import re
import shutil
import sys

from .models import SEVERITY_ORDER, ScanResult
from .probes import PORTS

# ------------------------------------------------------------- terminal

_COLORS = {"high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m",
           "info": "\033[2m", "none": "\033[32m", "dim": "\033[2m", "bold": "\033[1m",
           # Brand colours (see the brand sheet): Radar = watching, Alert = needs a look.
           "radar": "\033[38;2;46;196;182m", "alert": "\033[38;2;255;181;71m",
           # The owl's head: a lighter Deep, so the ears show on dark terminals
           # (plain "dim" turns grey or purple depending on the terminal theme).
           "head": "\033[38;2;111;134;166m",
           "reset": "\033[0m"}

TAGLINE = "See every device on your network. Catch what shouldn't be there."


def fancy_glyphs(stream=None) -> bool:
    """Whether the owl can use • ◣ ▾. The old Windows console (not Windows
    Terminal) lacks these glyphs; NOXIS_ASCII=1 forces the plain version.

    The eyes are a plain bullet, not ◉: terminal fonts rarely include ◉, so
    it comes from a wider fallback font and sits off-centre in its cell
    (the owl looks sideways). Every monospace font has a centred •."""
    if os.environ.get("NOXIS_ASCII"):
        return False
    stream = stream or sys.stdout
    enc = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
    if enc and enc not in ("utf8", "utf8sig"):
        return False
    if os.name == "nt" and hasattr(stream, "isatty") and stream.isatty():
        return bool(os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM")
                    or os.environ.get("ConEmuANSI"))
    return True


def banner(t: "Term", status: str, alert: bool = False) -> None:
    """The owl from the brand sheet: teal eyes while watching, amber on alert."""
    from . import __version__
    eyes = "alert" if alert else "radar"
    if fancy_glyphs(t.stream):
        ears, eye, beak, dot = " ◣   ◢", "(•) (•)", "   ▾", "·"
    else:
        ears, eye, beak, dot = "|\\   /|", "(o) (o)", "   v", "-"
    t.out(t.c("head", ears))
    t.out(t.c(eyes, eye) + "   " + t.c("bold", f"noxis {__version__}") + t.c("dim", f" {dot} {status}"))
    t.out(t.c("alert", beak) + "      " + t.c("dim", TAGLINE))
    t.out()


def alert_mark(t: "Term") -> str:
    """Amber owl eyes in front of each alert line."""
    return t.c("alert", "(•)(•)" if fancy_glyphs(t.stream) else "(!)(!)")


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR") or not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        os.system("")  # enables ANSI escape processing in Windows consoles
    return True


class Term:
    def __init__(self, stream=None):
        self.stream = stream = stream or sys.stdout
        self.color = _use_color(stream)

    def c(self, key: str, text: str) -> str:
        return f"{_COLORS[key]}{text}{_COLORS['reset']}" if self.color else text

    def out(self, text: str = "") -> None:
        print(text, file=self.stream, flush=True)  # live, even into a pipe or the systemd journal


def _terminal_width(t: "Term") -> int:
    """The terminal's width; effectively unlimited when output goes to a file."""
    stream = t.stream
    if hasattr(stream, "isatty") and stream.isatty():
        return max(80, shutil.get_terminal_size((120, 24)).columns - 1)
    return 1000


def _fit(text: str, width: int) -> str:
    text = text or ""
    return text if len(text) <= width else text[: width - 1] + "~"


_LEGAL = re.compile(
    r"[\s,.]*\b(co\.?,?\s*ltd|pte\.?\s*ltd|pvt\.?\s*ltd|private limited|ltd|limited|inc|"
    r"incorporated|corp|corporation|llc|gmbh|s\.?r\.?o|s\.?a|ag|b\.?v|oy|ab|plc|co)\b\.?",
    re.I)


def short_vendor(vendor: str) -> str:
    """'Raspberry Pi (Trading) Ltd' -> 'Raspberry Pi',
    'CLOUD NETWORK TECHNOLOGY SINGAPORE PTE. LTD.' -> 'Cloud Network Technology Singapore'."""
    v = re.sub(r"\s*\((?:trading|holdings?|shenzhen|hk|china)\)", "", vendor or "", flags=re.I)
    prev = None
    while prev != v:  # 'Co., Ltd.' takes two passes
        prev = v
        v = _LEGAL.sub("", v).strip(" ,.")
    if v.isupper() and len(v) > 4:
        v = " ".join(w if len(w) <= 3 or "-" in w else w.capitalize() for w in v.split())
    return v or vendor


def _drop_detail(label: str) -> str:
    """'Single-board computer (Raspberry Pi etc.)' -> 'Single-board computer'."""
    return re.sub(r"\s*\([^)]*\)$", "", label)


def table_widths(rows: list[list[str]], fixed: list[int], avail: int,
                 minimum: list[int]) -> tuple[list[list[str]], list[int]]:
    """Size the flexible columns (maker, type, name) to their content, then
    shrink to `avail` characters: first drop parenthetical detail from the
    type column, then trim the widest column."""
    def widths(rs):
        return [max([len(h)] + [len(r[i]) for r in rs]) for i, h in enumerate(("MAKER", "TYPE", "NAME"))]

    w = widths(rows)
    total = lambda w: sum(fixed) + sum(w) + len(fixed) + len(w) - 1  # noqa: E731
    if total(w) > avail:
        rows = [[r[0], _drop_detail(r[1]), r[2]] for r in rows]
        w = widths(rows)
    while total(w) > avail:
        i = max(range(3), key=lambda k: w[k] - minimum[k])
        if w[i] <= minimum[i]:
            break
        w[i] -= 1
    return rows, w


RISK_TAG = {"high": "HIGH", "medium": "MED", "low": "LOW", "info": "info", "none": "ok"}


def sorted_devices(result: ScanResult):
    return sorted(result.devices, key=lambda d: (-d.risk_rank, not d.is_gateway, not d.is_self,
                                                  [int(x) for x in d.ip.split(".")]))


CHECKLIST = [
    "Lights off, then sweep the room slowly with your phone flashlight: camera lenses "
    "reflect it as a tiny bright dot.",
    "In the dark, look through your phone's FRONT camera: many phones show night-vision "
    "infrared LEDs as faint purple or white dots.",
    "Check anything facing the bed, shower or toilet: smoke detectors, alarm clocks, USB "
    "chargers, air fresheners, picture frames, TV boxes, plants, vents.",
    "Look for devices plugged in where there's no obvious reason, or with a small hole or "
    "glossy black spot.",
    "If a camera-style hotspot showed up, walk around with your phone's Wi-Fi list open "
    "(or a Wi-Fi analyzer app): its signal rises as you get closer.",
    "Found one? Don't touch it. Photograph it in place, leave if you feel unsafe, and "
    "report it to the platform (Airbnb bans all indoor cameras) and, if needed, the police.",
]


_CHECK_TAG = {"ok": ("none", "ok  "), "warn": ("medium", "WARN"), "fail": ("high", "FAIL"),
              "skip": ("dim", "skip")}


def _check_lines(t: Term, checks) -> None:
    for c in checks:
        color, tag = _CHECK_TAG.get(c.status, ("dim", c.status))
        t.out(f"  {t.c(color, tag)} {c.name:<20} " + t.c("dim", c.detail))


def print_checks(checks, findings, header: str) -> None:
    """Output of `noxis check`."""
    t = Term()
    t.out()
    t.out(t.c("bold", header))
    _check_lines(t, checks)
    for f in sorted(findings, key=lambda f: -SEVERITY_ORDER[f.severity]):
        t.out()
        t.out(f"  {t.c(f.severity, RISK_TAG[f.severity])} {f.title}")
        t.out(t.c("dim", f"       {f.detail}"))
    if not any(f.severity in ("high", "medium") for f in findings):
        t.out()
        t.out(t.c("none", "No sign of anyone intercepting this connection."))


def _nearby_lines(t: Term, result: ScanResult) -> None:
    if not result.wifi_scanned:
        return
    flagged = result.flagged_aps()
    t.out()
    t.out(t.c("bold", "Nearby Wi-Fi") + t.c("dim", f"  ({len(result.nearby)} access points)"))
    if result.wifi_stale:
        from .wifi import STALE_NOTE
        t.out(t.c("medium", f"  Possibly out of date: {STALE_NOTE}"))
    if not result.nearby:
        t.out(t.c("dim", "  No nearby networks could be listed (Wi-Fi off, wired-only, or no permission)."))
        return
    if not flagged:
        t.out("  " + t.c("none", "Nothing suspicious nearby."))
    for ap in sorted(flagged, key=lambda a: (-max(SEVERITY_ORDER[f.severity] for f in a.findings),
                                             -(a.signal or 0))):
        top = max(ap.findings, key=lambda f: SEVERITY_ORDER[f.severity])
        sig = f"{ap.signal}%" if ap.signal is not None else "?"
        t.out(f"  {t.c(top.severity, RISK_TAG[top.severity])} '{ap.ssid or '(hidden)'}'  "
              + t.c("dim", f"{ap.bssid}  signal {sig}  {ap.band or ''} {ap.auth or ''}".rstrip()))
        for f in ap.findings:
            t.out(f"       - {t.c(f.severity, f.title)}")
            t.out(t.c("dim", f"         {f.detail}"))


def print_report(result: ScanResult, report_path: str | None = None,
                 checklist: bool = False, term: Term | None = None) -> None:
    t = term or Term()
    net = result.network
    counts = result.counts()
    sweep = result.rounds > 1
    t.out()
    kind = f"Noxis sweep ({result.rounds} rounds)" if sweep else "Noxis scan"
    t.out(t.c("bold", f"{kind}: {net.label}") +
          t.c("dim", f"  ({net.cidr}, gateway {net.gateway_ip or '?'}, {result.duration:.1f}s)"))
    summary = [f"{len(result.devices)} devices"]
    for sev in ("high", "medium", "low"):
        if counts[sev]:
            summary.append(t.c(sev, f"{counts[sev]} {sev}"))
    t.out("  " + " | ".join(summary))
    t.out()

    devices = sorted_devices(result)
    flex = []
    for d in devices:
        vendor = short_vendor(d.vendor) if d.vendor else ("(private MAC)" if d.randomized_mac else "?")
        name = d.display_name()
        if d.trusted:
            name = (name + " [trusted]").strip()
        if sweep and d.seen_rounds and not d.is_self:
            name = f"[seen {len(d.seen_rounds)}/{result.rounds}] {name}".strip()
        flex.append([vendor, d.type_label, name])
    ip_w = max([2] + [len(d.ip) for d in devices])
    fixed = [5, ip_w, 17, 5]  # RISK, IP, MAC, SURE?
    flex, (mw, tw, nw) = table_widths(flex, fixed, _terminal_width(t), minimum=[10, 14, 8])
    t.out(t.c("dim", f"{'RISK':<5} {'IP':<{ip_w}} {'MAC':<17} {'MAKER':<{mw}} {'TYPE':<{tw}} "
                     f"{'SURE?':<5} NAME"))
    for d, (vendor, dtype, name) in zip(devices, flex):
        conf = "-" if d.device_type == "unknown" else d.confidence
        line = (f"{RISK_TAG[d.risk]:<5} {d.ip:<{ip_w}} {(d.mac or '-'):<17} {_fit(vendor, mw):<{mw}} "
                f"{_fit(dtype, tw):<{tw}} {conf:<5} {_fit(name, nw)}")
        t.out(t.c(d.risk, line.rstrip()) if d.risk in ("high", "medium") else line.rstrip())

    hosting = [d for d in devices if d.services and not d.is_self]
    if hosting:
        t.out()
        t.out(t.c("bold", "Services"))
        for d in hosting:
            t.out(f"  {d.ip}  {d.display_name() or _drop_detail(d.type_label)}")
            for s in d.services:
                t.out(f"    {s.port:<6} {s.label()}" + t.c("dim", "  (trusted)" if s.trusted else ""))

    flagged = [d for d in sorted_devices(result)
               if any(f.severity != "info" for f in d.findings)]
    if flagged:
        t.out()
        t.out(t.c("bold", "Findings"))
        for d in flagged:
            t.out(f"  {t.c(d.risk, RISK_TAG[d.risk])} {d.ip}  {d.type_label}"
                  + (f": {d.vendor}" if d.vendor else "") + (f", {d.model}" if d.model else ""))
            for f in sorted(d.findings, key=lambda f: -SEVERITY_ORDER[f.severity]):
                if f.severity == "info":
                    continue
                t.out(f"       - {t.c(f.severity, f.title)}")
                t.out(t.c("dim", f"         {f.detail}"))

    if result.checks:
        t.out()
        t.out(t.c("bold", "Connection integrity"))
        _check_lines(t, result.checks)

    if result.findings:
        t.out()
        t.out(t.c("bold", "Network"))
        for f in sorted(result.findings, key=lambda f: -SEVERITY_ORDER[f.severity]):
            t.out(f"  {t.c(f.severity, RISK_TAG[f.severity])} {f.title}")
            t.out(t.c("dim", f"       {f.detail}"))

    _nearby_lines(t, result)

    serious = ("high", "medium")
    if not any(d.risk in serious for d in result.devices) and \
            not any(f.severity in serious for f in result.findings) and \
            not any(f.severity in serious for ap in result.nearby for f in ap.findings):
        t.out()
        t.out(t.c("none", "Nothing suspicious found on or around this network."))
    if checklist:
        t.out()
        t.out(t.c("bold", "Physical check (a network scan can't find everything)"))
        for i, item in enumerate(CHECKLIST, 1):
            t.out(f"  {i}. {item}")
    if report_path:
        t.out()
        t.out(t.c("dim", f"Full report: {report_path}"))


# ----------------------------------------------------------------- HTML

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#16181d;--muted:#5d6470;--line:#e3e6eb;
--high:#c62828;--high-bg:#fdecea;--med:#a15c00;--med-bg:#fff4e0;--low:#1f6f8b;--low-bg:#e6f4f8;
--ok:#2e7d32;--ok-bg:#e8f5e9;--chip:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#0e1827;--card:#14233A;--text:#e8edf3;--muted:#9fb0c8;
--line:#1F3655;--high:#ff6b6b;--high-bg:#3a1d1d;--med:#FFB547;--med-bg:#3a2c14;--low:#6cc4e0;
--low-bg:#15303a;--ok:#2EC4B6;--ok-bg:#12313a;--chip:#1F3655}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
.brand{background:#14233A;color:#fff}
.brand .in{max-width:1100px;margin:0 auto;padding:16px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.brand svg{flex:none}.brand .in>div{flex:1 1 220px;min-width:0}.word{font:600 30px/1 Sora,"Segoe UI",system-ui,sans-serif;letter-spacing:-.5px}
.tag{color:#9fb0c8;font-size:13px;margin-top:5px}
.state{margin-left:auto;font-size:12px;font-weight:700;padding:5px 11px;border-radius:99px;
text-transform:uppercase;letter-spacing:.06em}
.state.watch{background:rgba(46,196,182,.16);color:#2EC4B6}.state.alert{background:rgba(255,181,71,.16);color:#FFB547}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1,h2{font-family:Sora,"Segoe UI",system-ui,sans-serif}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}
footer{max-width:1100px;margin:0 auto;padding:0 16px 32px;color:var(--muted);font-size:13px;
display:flex;align-items:center;gap:8px}
.sub{color:var(--muted);margin:0 0 20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.stat b{display:block;font-size:26px}.stat span{color:var(--muted);font-size:13px}
.dev{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0;
border-left:4px solid var(--line)}
.dev.high{border-left-color:var(--high)}.dev.medium{border-left-color:var(--med)}
.dev.low{border-left-color:var(--low)}
.dev summary{cursor:pointer;padding:12px 14px;display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;
list-style:none}.dev summary::-webkit-details-marker{display:none}
.ip{font-family:ui-monospace,Consolas,monospace;font-weight:600;min-width:110px}
.type{font-weight:600}.muted{color:var(--muted)}
.badge{font-size:12px;font-weight:700;padding:2px 8px;border-radius:99px;text-transform:uppercase}
.b-high{background:var(--high-bg);color:var(--high)}.b-medium{background:var(--med-bg);color:var(--med)}
.b-low{background:var(--low-bg);color:var(--low)}.b-info,.b-none{background:var(--ok-bg);color:var(--ok)}
.body{padding:0 14px 14px;border-top:1px solid var(--line)}
.grid{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;margin-top:12px;font-size:14px}
.grid div:nth-child(odd){color:var(--muted)}
.chip{display:inline-block;background:var(--chip);border-radius:6px;padding:1px 7px;margin:2px 4px 2px 0;
font-size:13px;font-family:ui-monospace,Consolas,monospace}
.f{margin:10px 0 0;padding:10px 12px;border-radius:8px;background:var(--chip)}
.f b{display:block}.f p{margin:4px 0 0;color:var(--muted);font-size:14px}
.f.high{background:var(--high-bg)}.f.medium{background:var(--med-bg)}.f.low{background:var(--low-bg)}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px;margin-top:12px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 12px;
border-bottom:1px solid var(--line);white-space:nowrap}th{color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}.mono{font-family:ui-monospace,Consolas,monospace}
tr.r-high td:first-child{box-shadow:inset 4px 0 var(--high)}tr.r-medium td:first-child{box-shadow:inset 4px 0 var(--med)}
.cl li{margin:6px 0}
@media (max-width:600px){.grid{grid-template-columns:1fr}.grid div:nth-child(odd){margin-top:6px}}
"""


def _e(x) -> str:
    return html.escape(str(x)) if x is not None else ""


BRAND = {"night": "#14233A", "radar": "#2EC4B6", "alert": "#FFB547", "deep": "#1F3655"}


def owl_svg(size: int = 48, eyes: str = BRAND["radar"], head: str = BRAND["deep"],
            disc: str = "#2A4870", pupil_bg: str = BRAND["night"]) -> str:
    """The Noxis mark: raised ears, a two-lobed facial disc, radar-ring eyes
    and an amber beak. Self-contained SVG, so reports work offline."""
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100' width='{size}' height='{size}' "
        "role='img' aria-label='Noxis owl'>"
        f"<path d='M9 6 L38 29 Q50 25 62 29 L91 6 L93 58 Q93 94 50 94 Q7 94 7 58 Z' fill='{head}'/>"
        f"<circle cx='31' cy='58' r='24' fill='{disc}'/><circle cx='69' cy='58' r='24' fill='{disc}'/>"
        f"<circle cx='31' cy='58' r='19' fill='{eyes}'/><circle cx='31' cy='58' r='11.5' fill='{pupil_bg}'/>"
        f"<circle cx='31' cy='58' r='6.5' fill='{eyes}'/>"
        f"<circle cx='69' cy='58' r='19' fill='{eyes}'/><circle cx='69' cy='58' r='11.5' fill='{pupil_bg}'/>"
        f"<circle cx='69' cy='58' r='6.5' fill='{eyes}'/>"
        f"<path d='M50 71 L57 80 L50 90 L43 80 Z' fill='{BRAND['alert']}'/></svg>")


def ward_svg(height: int = 110, alert: bool = False, head: str = BRAND["night"],
             detail: str = BRAND["deep"], outline: str = "#ffffff") -> str:
    """Ward, the full owl from the brand sheet, perched on a branch. Teal eyes
    and branch ends while watching; amber, with alarm marks by the ears, on
    alert. `head`/`detail` let him stand out on a dark background."""
    accent = BRAND["alert"] if alert else BRAND["radar"]
    amber = BRAND["alert"]
    width = round(height * 320 / 515)
    eye = "".join(
        f"<circle cx='{x}' cy='225' r='62' fill='{detail}'/>" for x in (158, 272)) + "".join(
        f"<circle cx='{x}' cy='225' r='48' fill='{accent}'/><circle cx='{x}' cy='225' r='31' fill='{head}'/>"
        f"<circle cx='{x}' cy='225' r='16' fill='{accent}'/>" for x in (158, 272))
    chevrons = "".join(
        f"<path d='M{x - 13} {y - 5} L{x} {y + 5} L{x + 13} {y - 5}' fill='none' stroke='{head}' "
        "stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>"
        for x, y in ((191, 428), (239, 428), (215, 462), (191, 496), (239, 496)))
    alarm = "" if not alert else "".join(
        f"<path d='{d}' fill='none' stroke='{amber}' stroke-width='7' stroke-linecap='round'/>"
        for d in ("M66 92 A30 30 0 0 1 86 58", "M84 100 A16 16 0 0 1 95 82",
                  "M364 92 A30 30 0 0 0 344 58", "M346 100 A16 16 0 0 0 335 82"))
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='55 45 320 515' width='{width}' "
        f"height='{height}' role='img' aria-label='Ward, the Noxis owl'>{alarm}"
        # wings, then body, belly and feathers
        f"<path d='M122 343 Q84 430 142 520 Q156 430 122 343 Z' fill='{detail}'/>"
        f"<path d='M308 343 Q346 430 288 520 Q274 430 308 343 Z' fill='{detail}'/>"
        f"<ellipse cx='215' cy='443' rx='72' ry='92' fill='{head}'/>"
        f"<ellipse cx='215' cy='458' rx='58' ry='62' fill='{detail}'/>{chevrons}"
        # branch and feet
        f"<line x1='94' y1='543' x2='336' y2='543' stroke='{head}' stroke-width='10' stroke-linecap='round'/>"
        f"<circle cx='94' cy='543' r='11' fill='{accent}'/><circle cx='336' cy='543' r='11' fill='{accent}'/>"
        f"<rect x='168' y='524' width='46' height='14' rx='7' fill='{amber}'/>"
        f"<rect x='216' y='524' width='46' height='14' rx='7' fill='{amber}'/>"
        # head (a thin outline separates it from the body, as on the sheet), eyes, beak
        f"<path d='M90 96 L170 142 Q215 132 260 142 L340 96 L344 252 Q344 302 300 328 L215 360 "
        f"L130 328 Q86 302 86 252 Z' fill='{head}' stroke='{outline}' stroke-width='5' "
        "stroke-linejoin='round'/>"
        f"{eye}<path d='M215 258 L229 278 L215 300 L201 278 Z' fill='{amber}'/></svg>")


def _favicon(eyes: str) -> str:
    import base64
    svg = owl_svg(64, eyes, head=BRAND["night"], disc=BRAND["deep"]).encode()
    return f"data:image/svg+xml;base64,{base64.b64encode(svg).decode()}"


def _html_nearby(result: ScanResult) -> list[str]:
    if not result.wifi_scanned:
        return []
    parts = [f"<h2>Nearby Wi-Fi ({len(result.nearby)} access points)</h2>"]
    if result.wifi_stale:
        from .wifi import STALE_NOTE
        parts.append(f"<div class='f medium'><b>Possibly out of date</b><br>{_e(STALE_NOTE)}</div>")
    if not result.nearby:
        return parts + ["<p class='muted'>No nearby networks could be listed.</p>"]
    for ap in result.flagged_aps():
        for f in ap.findings:
            parts.append(f"<div class='f {f.severity}'><b>{_e(f.title)}: "
                         f"'{_e(ap.ssid or '(hidden)')}' ({_e(ap.bssid)}, signal {_e(ap.signal)}%)"
                         f"</b><p>{_e(f.detail)}</p></div>")
    parts.append("<div class='tw'><table><thead><tr><th>Network</th><th>BSSID</th><th>Maker</th>"
                 "<th>Signal</th><th>Band</th><th>Security</th>"
                 + ("<th>Seen</th>" if result.rounds > 1 else "") + "</tr></thead><tbody>")
    for ap in sorted(result.nearby, key=lambda a: -(a.signal or 0)):
        risk = max((f.severity for f in ap.findings), key=lambda s: SEVERITY_ORDER[s], default="none")
        mine = " (you)" if ap.bssid == result.network.bssid else ""
        parts.append(
            f"<tr class='r-{risk}'><td>{_e(ap.ssid or '(hidden)')}{mine}</td><td class='mono'>{_e(ap.bssid)}</td>"
            f"<td>{_e(ap.vendor or '')}</td><td>{_e(ap.signal)}%</td><td>{_e(ap.band or '')}</td>"
            f"<td>{_e(ap.auth or '')}</td>"
            + (f"<td>{len(ap.seen_rounds)}/{result.rounds}</td>" if result.rounds > 1 else "")
            + "</tr>")
    parts.append("</tbody></table></div>")
    return parts


def render_html(result: ScanResult) -> str:
    net = result.network
    counts = result.counts()
    sweep = result.rounds > 1
    kind = f"Noxis sweep ({result.rounds} rounds)" if sweep else "Noxis scan"
    when = result.started.replace("T", " ")
    if sweep:
        when += " to " + result.round_times[-1].replace("T", " ")[11:]
    serious = ("high", "medium")
    needs_look = (any(d.risk in serious for d in result.devices)
                  or any(f.severity in serious for f in result.findings)
                  or any(f.severity in serious for ap in result.nearby for f in ap.findings))
    eyes = BRAND["alert"] if needs_look else BRAND["radar"]
    state = ("<span class='state alert'>Needs a look</span>" if needs_look
             else "<span class='state watch'>All clear</span>")
    # Ward on the dark header: lighter navy than the band so he stands out.
    ward = ward_svg(104, needs_look, head="#1F3655", detail="#2E4D78", outline=BRAND["night"])
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<link rel='icon' href='{_favicon(eyes)}'>",
        f"<title>{kind}: {_e(net.label)}</title><style>{_CSS}</style></head><body>",
        f"<header class='brand'><div class='in'>{ward}<div><div class='word'>noxis</div>"
        f"<div class='tag'>{_e(TAGLINE)}</div></div>{state}</div></header><main>",
        f"<h1>{kind}: {_e(net.label)}</h1>",
        f"<p class='sub'>{_e(net.cidr)} &middot; gateway {_e(net.gateway_ip)} &middot; "
        f"{_e(when)} &middot; {result.duration:.1f}s scanning</p>",
        "<div class='stats'>",
        f"<div class='stat'><b>{len(result.devices)}</b><span>devices</span></div>",
        f"<div class='stat'><b style='color:var(--high)'>{counts['high']}</b><span>high risk</span></div>",
        f"<div class='stat'><b style='color:var(--med)'>{counts['medium']}</b><span>medium risk</span></div>",
        f"<div class='stat'><b style='color:var(--low)'>{counts['low']}</b><span>low risk</span></div>",
        "</div>",
    ]
    if result.checks:
        parts.append("<h2>Connection integrity</h2><div class='tw'><table><tbody>")
        for c in result.checks:
            badge = {"ok": "none", "warn": "medium", "fail": "high"}.get(c.status, "info")
            parts.append(f"<tr><td><span class='badge b-{badge}'>{_e(c.status)}</span></td>"
                         f"<td><b>{_e(c.name)}</b></td><td style='white-space:normal'>{_e(c.detail)}</td></tr>")
        parts.append("</tbody></table></div>")
    if result.findings:
        parts.append("<h2>Network</h2>")
        for f in sorted(result.findings, key=lambda f: -SEVERITY_ORDER[f.severity]):
            parts.append(f"<div class='f {f.severity}'><b>{_e(f.title)}</b><p>{_e(f.detail)}</p></div>")

    parts.append("<h2>Devices</h2>")
    for d in sorted_devices(result):
        open_attr = " open" if d.risk in ("high", "medium") else ""
        vendor = d.vendor or ("Private (randomized) MAC" if d.randomized_mac else "Unknown maker")
        parts.append(f"<details class='dev {d.risk}'{open_attr}><summary>")
        parts.append(f"<span class='badge b-{d.risk}'>{RISK_TAG[d.risk]}</span>")
        parts.append(f"<span class='ip'>{_e(d.ip)}</span><span class='type'>{_e(d.type_label)}</span>")
        parts.append(f"<span class='muted'>{_e(vendor)}</span>")
        if sweep and d.seen_rounds and not d.is_self:
            parts.append(f"<span class='muted'>seen {len(d.seen_rounds)}/{result.rounds}</span>")
        name = d.display_name()
        if name:
            parts.append(f"<span>{_e(name)}{' &check; trusted' if d.trusted else ''}</span>")
        parts.append("</summary><div class='body'><div class='grid'>")
        rows = [
            ("MAC", d.mac or "-"),
            ("Identified as", f"{d.type_label} ({d.confidence} confidence)"),
            ("Model", d.model),
            ("Names", ", ".join(d.hostnames + ([d.netbios_name] if d.netbios_name else []))),
            ("Why", "; ".join(d.evidence)),
            ("Ping TTL", d.ttl),
        ]
        for label, value in rows:
            if value:
                parts.append(f"<div>{label}</div><div>{_e(value)}</div>")
        if d.services:
            chips = "".join(f"<span class='chip'>{s.port} {_e(s.label())}{' ✓' if s.trusted else ''}</span>"
                            for s in d.services)
            parts.append(f"<div>Services</div><div>{chips}</div>")
        elif d.open_ports:
            chips = "".join(f"<span class='chip'>{p} {_e(PORTS.get(p, ''))}</span>" for p in d.open_ports)
            parts.append(f"<div>Open ports</div><div>{chips}</div>")
        if d.mdns_services:
            chips = "".join(f"<span class='chip'>{_e(s)}</span>" for s in d.mdns_services)
            parts.append(f"<div>Announces</div><div>{chips}</div>")
        for port, b in sorted(d.banners.items()):
            text = " | ".join(v for k, v in b.items() if k != "kind" and v)
            parts.append(f"<div>Port {port} says</div><div>{_e(text)}</div>")
        parts.append("</div>")
        for f in sorted(d.findings, key=lambda f: -SEVERITY_ORDER[f.severity]):
            parts.append(f"<div class='f {f.severity}'><b>{_e(f.title)}</b><p>{_e(f.detail)}</p></div>")
        parts.append("</div></details>")
    parts += _html_nearby(result)
    if sweep:
        parts.append("<h2>Physical check</h2><p class='muted'>A network scan can't find a camera "
                     "that records to an SD card, uses cellular, or is switched off.</p><ol class='cl'>")
        parts += [f"<li>{_e(item)}</li>" for item in CHECKLIST]
        parts.append("</ol>")
    from . import __version__
    parts.append(f"</main><footer>{owl_svg(18, eyes, head='currentColor', disc='currentColor')}"
                 f"Made by noxis {_e(__version__)} &middot; {_e(when)}</footer></body></html>")
    return "".join(parts)
