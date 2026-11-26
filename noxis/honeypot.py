"""Honeypot: decoy services that nothing legitimate should ever touch.

Two layers:

* Decoy listeners (any OS, no admin): fake Telnet/FTP/SSH/database/etc.
  ports. A full connection to one means someone is probing this machine;
  touching several means a port scan. What the visitor types (e.g. login
  attempts) is recorded.
* Packet watcher (Linux as root, e.g. on a Raspberry Pi): sees stealth SYN
  scans that never complete a connection, and ARP sweeps, where one device
  asks for dozens of addresses in seconds (how nmap and friends map a LAN).
* Counter watcher (Windows, no admin): a stealth SYN scan never completes a
  connection, so the decoys never see it. Windows still counts those
  half-open attempts in its TCP statistics; a burst of them means a scan.
  Windows doesn't say who sent them, so these alerts have no source.
"""

from __future__ import annotations

import asyncio
import json
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from typing import Callable

from .util import append_line, failed_connects

# port -> (service, banner sent on connect, reply after the visitor's first line)
DECOYS: dict[int, tuple[str, bytes, bytes]] = {
    21: ("FTP", b"220 (vsFTPd 3.0.3)\r\n", b"331 Please specify the password.\r\n"),
    23: ("Telnet", b"\r\nUbuntu 22.04.3 LTS\r\nserver login: ", b"Password: "),
    1433: ("MS SQL Server", b"", b""),
    2222: ("SSH", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n", b""),
    2323: ("Telnet (IoT)", b"\r\nlogin: ", b"Password: "),
    3306: ("MySQL", b"", b""),
    5555: ("Android ADB", b"", b""),
    5900: ("VNC", b"RFB 003.008\n", b""),
    6379: ("Redis", b"", b"-NOAUTH Authentication required.\r\n"),
    7547: ("TR-069 router management", b"", b""),
    8291: ("MikroTik Winbox", b"", b""),
    9200: ("Elasticsearch", b"", b""),
    27017: ("MongoDB", b"", b""),
}

# The lure: a fake web login. Port 80 is one of the ports nmap knocks on to
# decide whether a device is online at all, so this makes this computer show
# up in casual scans (and walk into the decoys). Off unless asked for, since
# being invisible is usually better.
_LURE_PAGE = (b"<html><head><title>Login</title></head><body><form method=post action=/login>"
              b"User <input name=user> Password <input type=password name=pass> "
              b"<input type=submit value=Login></form></body></html>")
LURES: dict[int, tuple[str, bytes, bytes]] = {
    80: ("web login page", b"",
         b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.59\r\nContent-Type: text/html\r\n"
         b"Content-Length: " + str(len(_LURE_PAGE)).encode() + b"\r\nConnection: close\r\n\r\n"
         + _LURE_PAGE),
}
LURE_PORTS = sorted(LURES)


@dataclass
class HoneypotEvent:
    when: float
    kind: str  # connect | syn | arp
    src_ip: str
    src_mac: str | None = None
    dst_port: int | None = None
    service: str | None = None
    data: str = ""
    target_ip: str | None = None


@dataclass
class HoneypotAlert:
    severity: str
    title: str
    src_ip: str
    detail: str
    ports: list[int] = field(default_factory=list)


def _printable(raw: bytes, limit: int = 200) -> str:
    text = raw.decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() else " " for ch in text).strip()[:limit]


class Detector:
    """Turns raw events into alerts. Pure logic: no sockets, easy to test."""

    def __init__(self, own_ips: set[str] | None = None, own_macs: set[str] | None = None,
                 scan_ports: int = 3, scan_window: float = 120,
                 syn_ports: int = 10, syn_window: float = 15,
                 arp_targets: int = 25, arp_window: float = 10,
                 half_open: int = 4, half_open_window: float = 20,
                 rst_burst: int = 100, rst_window: float = 10,
                 quiet: float = 600):
        self.own_ips = own_ips or set()
        self.own_macs = own_macs or set()
        self.scan_ports, self.scan_window = scan_ports, scan_window
        self.syn_ports, self.syn_window = syn_ports, syn_window
        self.arp_targets, self.arp_window = arp_targets, arp_window
        self.half_open, self.half_open_window = half_open, half_open_window
        self.rst_burst, self.rst_window = rst_burst, rst_window
        self.quiet = quiet
        self._counts: deque = deque()  # (time, passive, fails, rsts)
        self._touches: dict[str, deque] = defaultdict(deque)  # src -> (time, port)
        self._syns: dict[str, deque] = defaultdict(deque)
        self._arps: dict[str, deque] = defaultdict(deque)  # mac -> (time, target)
        self._last_alert: dict[tuple, float] = {}

    def _cooldown(self, key: tuple, now: float) -> bool:
        """True if this alert was already raised recently."""
        last = self._last_alert.get(key)
        if last is not None and now - last < self.quiet:
            return True
        self._last_alert[key] = now
        return False

    @staticmethod
    def _window(q: deque, now: float, span: float) -> None:
        while q and now - q[0][0] > span:
            q.popleft()

    def counters(self, now: float, passive: int, fails: int, rsts: int) -> list[HoneypotAlert]:
        """One poll of the Windows TCP counters: deltas since the last poll, with
        connections the decoys accepted already taken off `passive` and
        Noxis's own failed outgoing connects taken off `fails`."""
        q = self._counts
        q.append((now, passive, fails, rsts))
        self._window(q, now, max(self.half_open_window, self.rst_window))
        recent = [e for e in q if now - e[0] <= self.half_open_window]
        ho = half_open_from(sum(e[1] for e in recent), sum(e[2] for e in recent))
        rs = sum(e[3] for e in q if now - e[0] <= self.rst_window)
        if ho >= self.half_open and not self._cooldown(("stealth",), now):
            return [HoneypotAlert(
                "high", "Stealth port scan detected", "",
                f"{ho} connections to this computer were started and abandoned halfway within "
                f"{int(self.half_open_window)}s. That's how stealth scans (nmap's default "
                "mode, masscan) probe for open ports without ever connecting. Windows doesn't "
                "record who sent them; Noxis on Linux (as root) can name the scanner.")]
        if rs >= self.rst_burst and not self._cooldown(("stealth",), now):
            return [HoneypotAlert(
                "high", "Port scan detected", "",
                f"This computer turned away {rs} connection attempts to closed ports within "
                f"{int(self.rst_window)}s. Something is scanning it. Windows doesn't record "
                "who; Noxis on Linux (as root) can name the scanner.")]
        return []

    def handle(self, ev: HoneypotEvent) -> list[HoneypotAlert]:
        if ev.kind == "connect":
            return self._connect(ev)
        if ev.kind == "syn":
            return self._syn(ev)
        if ev.kind == "arp":
            return self._arp(ev)
        return []

    def _connect(self, ev: HoneypotEvent) -> list[HoneypotAlert]:
        now, src = ev.when, ev.src_ip
        q = self._touches[src]
        q.append((now, ev.dst_port))
        self._window(q, now, self.scan_window)
        ports = sorted({p for _, p in q})
        alerts = []
        if len(ports) >= self.scan_ports:
            if not self._cooldown(("scan", src), now):
                alerts.append(HoneypotAlert(
                    "high", "Port scan hit the honeypot", src,
                    f"{src} connected to {len(ports)} decoy ports so far ({', '.join(map(str, ports))}) "
                    f"within {int(self.scan_window)}s. Something is scanning this machine for "
                    "weaknesses (nmap, a worm, or an infected device).", ports))
        elif not self._cooldown(("touch", src, ev.dst_port), now):
            said = f" It sent: \"{ev.data}\"" if ev.data else ""
            if ev.dst_port in LURES:
                alerts.append(HoneypotAlert(
                    "medium", f"Visit to the lure {ev.service}", src,
                    f"{src} opened the fake {ev.service} on port {ev.dst_port}. Smart TVs and "
                    "printers looking around sometimes do this, so one visit is only a hint; a "
                    f"scan would also hit the other decoys.{said}", [ev.dst_port]))
            else:
                alerts.append(HoneypotAlert(
                    "high", f"Connection to decoy {ev.service}", src,
                    f"{src} connected to the fake {ev.service} service on port {ev.dst_port}. Nothing "
                    f"legitimate uses it, so this is someone probing.{said}", [ev.dst_port]))
        return alerts

    def _syn(self, ev: HoneypotEvent) -> list[HoneypotAlert]:
        if ev.src_ip in self.own_ips:
            return []
        now, src = ev.when, ev.src_ip
        q = self._syns[src]
        q.append((now, ev.dst_port))
        self._window(q, now, self.syn_window)
        ports = {p for _, p in q}
        if len(ports) >= self.syn_ports and not self._cooldown(("syn", src), now):
            return [HoneypotAlert(
                "high", "Port scan detected", src,
                f"{src} tried {len(ports)} different ports on this machine so far, within "
                f"{int(self.syn_window)}s. Seen at packet level, so this also catches stealth "
                "SYN scans (nmap -sS, masscan) that never complete a connection.",
                sorted(ports)[:20])]
        return []

    def _arp(self, ev: HoneypotEvent) -> list[HoneypotAlert]:
        if not ev.src_mac or ev.src_mac in self.own_macs or ev.target_ip == ev.src_ip:
            return []  # our own scans, or a gratuitous ARP announcement
        now, mac = ev.when, ev.src_mac
        q = self._arps[mac]
        q.append((now, ev.target_ip))
        self._window(q, now, self.arp_window)
        targets = {t for _, t in q}
        if len(targets) >= self.arp_targets and not self._cooldown(("arp", mac), now):
            return [HoneypotAlert(
                "high", "Network sweep detected", ev.src_ip,
                f"{ev.src_ip} ({mac}) asked for {len(targets)} different addresses so far, within "
                f"{int(self.arp_window)}s. That's someone mapping every device on the network "
                "(nmap host discovery, arp-scan, Noxis itself).")]
        return []


# ---------------------------------------------------------- packet parsing


def parse_frame(frame: bytes):
    """Ethernet frame -> ("arp", op, sha, spa, tpa) | ("tcp", src, dst, dport, flags) | None."""
    if len(frame) < 14:
        return None
    etype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if etype == 0x8100 and len(frame) >= 18:  # VLAN tag
        etype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if etype == 0x0806 and len(frame) >= off + 28:
        op = struct.unpack("!H", frame[off + 6:off + 8])[0]
        sha = ":".join(f"{b:02x}" for b in frame[off + 8:off + 14])
        spa = socket.inet_ntoa(frame[off + 14:off + 18])
        tpa = socket.inet_ntoa(frame[off + 24:off + 28])
        return ("arp", op, sha, spa, tpa)
    if etype == 0x0800 and len(frame) >= off + 20:
        ihl = (frame[off] & 0x0F) * 4
        if frame[off + 9] != 6 or len(frame) < off + ihl + 14:
            return None
        src = socket.inet_ntoa(frame[off + 12:off + 16])
        dst = socket.inet_ntoa(frame[off + 16:off + 20])
        t = off + ihl
        dport = struct.unpack("!H", frame[t + 2:t + 4])[0]
        flags = frame[t + 13]
        return ("tcp", src, dst, dport, flags)
    return None


SYN, ACK = 0x02, 0x10

# Classic BPF program for the packet watcher, run by the kernel on every frame
# so Python only sees what the detector uses: ARP requests, and incoming TCP
# segments with SYN set and ACK clear. Everything this machine sends (its own
# scans: thousands of packets) and all other traffic is dropped in the kernel,
# so a busy moment can't overflow the socket's queue and hide a real scan.
_SKF_AD_PKTTYPE = 0xFFFFF000 + 4  # SKF_AD_OFF + SKF_AD_PKTTYPE
_PACKET_OUTGOING = 4
SNIFF_FILTER = [
    # (code, jt, jf, k); jumps count from the next instruction
    (0x20, 0, 0, _SKF_AD_PKTTYPE),   # 0  A = packet type
    (0x15, 14, 0, _PACKET_OUTGOING),  # 1  sent by us -> drop
    (0x28, 0, 0, 12),                # 2  A = EtherType
    (0x15, 0, 2, 0x0806),            # 3  ARP? else -> 6
    (0x28, 0, 0, 20),                # 4  A = ARP opcode
    (0x15, 9, 10, 1),                # 5  request -> accept, else drop
    (0x15, 0, 9, 0x0800),            # 6  IPv4? else drop
    (0x30, 0, 0, 23),                # 7  A = IP protocol
    (0x15, 0, 7, 6),                 # 8  TCP? else drop
    (0x28, 0, 0, 20),                # 9  A = flags + fragment offset
    (0x45, 5, 0, 0x1FFF),            # 10 a later fragment -> drop
    (0xB1, 0, 0, 14),                # 11 X = IP header length
    (0x50, 0, 0, 27),                # 12 A = TCP flags
    (0x54, 0, 0, SYN | ACK),         # 13 A &= SYN|ACK
    (0x15, 0, 1, SYN),               # 14 SYN without ACK -> accept, else drop
    (0x06, 0, 0, 0x40000),           # 15 accept
    (0x06, 0, 0, 0),                 # 16 drop
]
SOL_PACKET, PACKET_STATISTICS, SO_ATTACH_FILTER = 263, 6, 26


def attach_filter(sock: socket.socket, program=SNIFF_FILTER) -> bool:
    """Attach a classic BPF program to a packet socket. False if the kernel refused."""
    import ctypes
    raw = b"".join(struct.pack("HBBI", *insn) for insn in program)
    buf = ctypes.create_string_buffer(raw, len(raw))
    fprog = struct.pack("HL", len(program), ctypes.addressof(buf))  # struct sock_fprog
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        return True
    except OSError:
        return False


def read_drops(sock: socket.socket) -> int:
    """Frames the kernel dropped because the queue was full, since the last call."""
    try:
        _, drops = struct.unpack("II", sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
        return drops
    except OSError:
        return 0


def frame_to_event(frame: bytes, local_ip: str, now: float) -> HoneypotEvent | None:
    p = parse_frame(frame)
    if p is None:
        return None
    if p[0] == "arp" and p[1] == 1:  # ARP request
        _, _, sha, spa, tpa = p
        return HoneypotEvent(now, "arp", spa, src_mac=sha, target_ip=tpa)
    if p[0] == "tcp":
        _, src, dst, dport, flags = p
        if dst == local_ip and flags & SYN and not flags & ACK:
            return HoneypotEvent(now, "syn", src, dst_port=dport)
    return None


# ------------------------------------------------------- Windows counters


def tcp_counters() -> tuple[int, int, int] | None:
    """(PassiveOpens, AttemptFails, OutRsts) from Windows' IPv4 TCP statistics."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes
    names = ["RtoAlgorithm", "RtoMin", "RtoMax", "MaxConn", "ActiveOpens", "PassiveOpens",
             "AttemptFails", "EstabResets", "CurrEstab", "InSegs", "OutSegs", "RetransSegs",
             "InErrs", "OutRsts", "NumConns"]

    class Stats(ctypes.Structure):
        _fields_ = [(n, wintypes.DWORD) for n in names]

    st = Stats()
    try:
        if ctypes.windll.iphlpapi.GetTcpStatisticsEx(ctypes.byref(st), 2) != 0:  # AF_INET
            return None
    except (OSError, AttributeError):
        return None
    return st.PassiveOpens, st.AttemptFails, st.OutRsts


def half_open_from(passive: int, fails: int) -> int:
    """Half-open inbound attempts.

    `passive` (incoming attempts the decoys didn't accept) also includes
    ordinary localhost connections between apps. `fails` (failed attempts
    minus Noxis's own failed outgoing connects) also includes other apps'
    failed outgoing connections. A stealth scan raises both, so the smaller
    of the two is a safe estimate.
    """
    return max(0, min(passive, fails))


# ------------------------------------------------------------------ runtime


class Honeypot:
    def __init__(self, local_ip: str, local_mac: str | None,
                 on_alert: Callable[[HoneypotAlert], None],
                 log_path=None, ports: list[int] | None = None, bind: str = "0.0.0.0",
                 lure: bool = False, on_note: Callable[[str], None] | None = None):
        self.bind = bind
        self.local_ip = local_ip
        self.on_alert = on_alert
        self.on_note = on_note or (lambda msg: print(msg, flush=True))
        self.filtered = False  # kernel packet filter attached
        self.dropped = 0       # frames the packet watcher missed
        self.log_path = log_path
        self.ports = ports or sorted(DECOYS)
        if lure:
            self.ports = sorted(set(self.ports) | set(LURE_PORTS))
        self.listening: list[int] = []
        self.skipped: dict[int, str] = {}
        self.sniffing = False
        self.sniff_note = ""
        self.counting = False  # Windows half-open scan watcher
        self._accepted = 0
        self._read_counters = tcp_counters
        self._own_failed = failed_connects
        self._poll = 1.0
        self.detector = Detector(own_ips={local_ip}, own_macs={local_mac} if local_mac else set())
        self._lock = threading.Lock()
        self._ready = threading.Event()

    def set_local(self, local_ip: str, local_mac: str | None) -> None:
        """This machine's address changed (DHCP renewal, another network):
        watch for scans of the new one, and don't flag our own traffic."""
        with self._lock:
            self.local_ip = local_ip
            self.detector.own_ips = {local_ip}
            self.detector.own_macs = {local_mac} if local_mac else set()

    def _record(self, ev: HoneypotEvent) -> None:
        with self._lock:
            alerts = self.detector.handle(ev)
            if self.log_path and ev.kind == "connect":
                append_line(self.log_path, json.dumps(asdict(ev)))
        for a in alerts:
            self.on_alert(a)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
        peer = writer.get_extra_info("peername") or ("?", 0)
        with self._lock:
            self._accepted += 1
        service, banner, reply = DECOYS.get(port) or LURES.get(port) or ("Unknown", b"", b"")
        captured = b""
        try:
            if banner:
                writer.write(banner)
                await writer.drain()
            for step in range(2):
                try:
                    chunk = await asyncio.wait_for(reader.read(512), 8)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                captured += chunk
                if step == 0 and reply:
                    writer.write(reply)
                    await writer.drain()
            if service.startswith("Telnet") and captured:
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
        self._record(HoneypotEvent(time.time(), "connect", peer[0], dst_port=port,
                                   service=service, data=_printable(captured)))

    async def _main(self, stop: threading.Event):
        servers = []
        for port in self.ports:
            try:
                srv = await asyncio.start_server(
                    lambda r, w, p=port: self._serve(r, w, p), host=self.bind, port=port)
                servers.append(srv)
                self.listening.append(port)
            except PermissionError:
                self.skipped[port] = "needs root (ports below 1024)"
            except OSError:
                self.skipped[port] = "already in use by a real service"
        self._ready.set()
        while not stop.is_set():
            await asyncio.sleep(0.5)
        for srv in servers:
            srv.close()

    def _sniff(self, stop: threading.Event):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        except (AttributeError, PermissionError, OSError) as e:
            self.sniff_note = ("needs root, or run it with `noxis service install`"
                              if isinstance(e, PermissionError) else "not supported here")
            return
        self.filtered = attach_filter(s)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)  # capped by the kernel
        except OSError:
            pass
        read_drops(s)  # start counting from now
        self.sniffing = True
        s.settimeout(1.0)
        next_check = time.monotonic() + 60
        while not stop.is_set():
            try:
                frame = s.recv(2048)
            except socket.timeout:
                frame = None
            except OSError:
                break
            if frame:
                ev = frame_to_event(frame, self.local_ip, time.time())
                if ev:
                    self._record(ev)
            if time.monotonic() >= next_check:
                next_check = time.monotonic() + 60
                if dropped := read_drops(s):
                    self.dropped += dropped
                    self.on_note(f"Packet watcher missed {dropped} packets in the last minute "
                                 "(this computer was too busy): a scan in that time may have "
                                 "gone unnoticed.")
        s.close()

    def _watch_counters(self, stop: threading.Event):
        prev = self._read_counters()
        if prev is None:
            return
        with self._lock:
            prev_acc = self._accepted
        prev_own = self._own_failed()
        while not stop.wait(self._poll):
            cur = self._read_counters()
            if cur is None:
                continue
            own = self._own_failed()
            with self._lock:
                acc = self._accepted
            d = [(c - p) % 2**32 for c, p in zip(cur, prev)]
            passive, fails = d[0] - (acc - prev_acc), d[1] - (own - prev_own)
            prev, prev_acc, prev_own = cur, acc, own
            if not (passive or fails or d[2]):
                continue
            with self._lock:
                alerts = self.detector.counters(time.time(), passive, fails, d[2])
            for a in alerts:
                self.on_alert(a)

    def start(self, stop: threading.Event) -> None:
        """Start listeners (and the packet watcher on Linux) in background threads."""
        threading.Thread(target=lambda: asyncio.run(self._main(stop)), daemon=True,
                         name="noxis-honeypot").start()
        if sys.platform.startswith("linux"):
            threading.Thread(target=self._sniff, args=(stop,), daemon=True,
                             name="noxis-sniffer").start()
        else:
            self.sniff_note = "needs Linux, running as root"
        if sys.platform == "win32" and self._read_counters() is not None:
            self.counting = True
            threading.Thread(target=self._watch_counters, args=(stop,), daemon=True,
                             name="noxis-counters").start()
        self._ready.wait(10)
        time.sleep(0.2)  # let the sniffer report whether it started
