"""Find live hosts: ping, ARP (SendARP on Windows), ARP table, TCP touches,
reverse DNS and NetBIOS names."""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
import socket
import struct

from .util import IPV4_RE, IS_MAC, IS_WINDOWS, MAC_RE, normalize_mac, note_failed_connect, run, is_unicast_mac

# --------------------------------------------------------------------- ping

_TTL_RE = re.compile(r"ttl[=\s:]*(\d+)", re.I)


async def ping(ip: str, timeout_ms: int, sem: asyncio.Semaphore) -> int | None:
    """Return the reply TTL, or None if no echo reply."""
    if IS_WINDOWS:
        args = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif IS_MAC:
        args = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]
    kwargs = {}
    if IS_WINDOWS:
        import subprocess

        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    async with sem:
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                **kwargs,
            )
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), timeout_ms / 1000 + 3)
            except BaseException:
                # Timed out or cancelled (the scan failed elsewhere): don't
                # leave ping.exe running, or shutting down waits for it.
                if proc.returncode is None:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                raise
        except (OSError, asyncio.TimeoutError):
            return None
    for line in out.decode(errors="replace").splitlines():
        # Must be a reply *from the target* carrying a TTL (Windows prints
        # "Reply from <us>: Destination host unreachable" with no TTL).
        if ip in line:
            m = _TTL_RE.search(line)
            if m:
                return int(m.group(1))
    return None


# ---------------------------------------------------------------- TCP touch

async def tcp_state(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> str | None:
    """'open', 'closed' (RST - host is alive) or None (no answer)."""
    async with sem:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except ConnectionRefusedError:
            note_failed_connect()
            return "closed"
        except (asyncio.TimeoutError, OSError):
            note_failed_connect()
            return None
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (asyncio.TimeoutError, OSError):
            pass
        return "open"


# ---------------------------------------------------------- Windows SendARP

def _sendarp_one(ip: str) -> str | None:
    import ctypes

    iphlpapi = ctypes.windll.iphlpapi
    iphlpapi.SendARP.argtypes = [
        ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)
    ]
    dest = struct.unpack("<I", socket.inet_aton(ip))[0]
    buf = (ctypes.c_ubyte * 8)()
    length = ctypes.c_ulong(6)
    if iphlpapi.SendARP(dest, 0, ctypes.byref(buf), ctypes.byref(length)) != 0:
        return None
    if length.value != 6:
        return None
    return ":".join(f"{b:02x}" for b in buf[:6])


async def sendarp_sweep(ips: list[str]) -> dict[str, str]:
    """ARP every address directly. Finds devices that ignore ping and TCP."""
    if not IS_WINDOWS:
        return {}
    loop = asyncio.get_running_loop()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=128)
    try:
        macs = await asyncio.gather(
            *(loop.run_in_executor(pool, _sendarp_one, ip) for ip in ips),
            return_exceptions=True,
        )
    finally:
        pool.shutdown(wait=False)
    found = {}
    for ip, mac in zip(ips, macs):
        if isinstance(mac, str):
            mac = normalize_mac(mac)
            if mac and is_unicast_mac(mac):
                found[ip] = mac
    return found


# ---------------------------------------------------------------- ARP table

def parse_arp_output(text: str) -> dict[str, str]:
    """Parse `arp -a` (Windows/macOS), `ip neigh` or /proc/net/arp output."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        low = line.lower()
        if any(word in low for word in ("incomplete", "failed", "interface:")):
            continue
        ip_m = IPV4_RE.search(line)
        mac_m = MAC_RE.search(line)
        if not (ip_m and mac_m):
            continue
        mac = normalize_mac(mac_m.group(1))
        if mac and is_unicast_mac(mac):
            table[ip_m.group(1)] = mac
    return table


def read_arp_table() -> dict[str, str]:
    if IS_WINDOWS or IS_MAC:
        return parse_arp_output(run(["arp", "-an" if IS_MAC else "-a"]))
    text = run(["ip", "neigh"])
    if not text:
        try:
            with open("/proc/net/arp") as fh:
                text = fh.read()
        except OSError:
            text = ""
    return parse_arp_output(text)


# -------------------------------------------------------------- reverse DNS

async def reverse_dns(ips: list[str], timeout: float = 2.5) -> dict[str, str]:
    loop = asyncio.get_running_loop()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=32)

    async def one(ip):
        try:
            name = await asyncio.wait_for(
                loop.run_in_executor(pool, socket.gethostbyaddr, ip), timeout
            )
            return ip, name[0]
        except (OSError, asyncio.TimeoutError):
            return ip, None

    try:
        results = await asyncio.gather(*(one(ip) for ip in ips))
    finally:
        pool.shutdown(wait=False)
    return {ip: name for ip, name in results if name and name != ip}


# ------------------------------------------------------------------ NetBIOS

_NBSTAT_QUERY = (
    b"\x57\x44\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
    + b"\x00\x21\x00\x01"
)


def parse_nbstat(data: bytes) -> tuple[str | None, str | None]:
    """Return (computer name, workgroup) from a NetBIOS node-status reply."""
    try:
        off = 12 + 34 + 10  # header + encoded name + type/class/ttl/rdlength
        count = data[off]
        off += 1
        name = group = None
        for _ in range(count):
            raw = data[off:off + 18]
            off += 18
            label = raw[:15].decode("ascii", "replace").strip()
            suffix = raw[15]
            flags = struct.unpack("!H", raw[16:18])[0]
            is_group = bool(flags & 0x8000)
            if suffix == 0x00 and not is_group and not name:
                name = label
            elif suffix == 0x00 and is_group and not group:
                group = label
        return name, group
    except (IndexError, struct.error):
        return None, None


def netbios_names(ips: list[str], local_ip: str, wait: float = 1.5) -> dict[str, tuple]:
    import time

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out: dict[str, tuple] = {}
    try:
        s.bind((local_ip, 0))
        s.settimeout(0.2)
        for ip in ips:
            try:
                s.sendto(_NBSTAT_QUERY, (ip, 137))
            except OSError:
                pass
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                # Windows raises ConnectionResetError for ICMP port-unreachable.
                continue
            name, group = parse_nbstat(data)
            if name:
                out[addr[0]] = (name, group)
    finally:
        s.close()
    return out
