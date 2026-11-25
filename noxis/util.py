"""Small shared helpers."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"

MAC_RE = re.compile(
    r"(?<![0-9a-fA-F:-])([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})(?![0-9a-fA-F:-])"
)
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def run(args: list[str], timeout: float = 15) -> str:
    """Run a command and return its stdout as text ("" on any failure)."""
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.decode(errors="replace")


def normalize_mac(mac: str | None) -> str | None:
    """'7C-A9-6B-12-34-56' / '0:1b:2:...' -> '7c:a9:6b:12:34:56'."""
    if not mac:
        return None
    parts = re.split(r"[:-]", mac.strip())
    if len(parts) != 6 or not all(1 <= len(p) <= 2 for p in parts):
        return None
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return None


def is_randomized_mac(mac: str) -> bool:
    """Locally-administered bit set: phones' 'private Wi-Fi address' etc."""
    return bool(int(mac[:2], 16) & 0x02)


def is_unicast_mac(mac: str) -> bool:
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    return not (int(mac[:2], 16) & 0x01)


# Outgoing connection attempts that failed (refused or timed out). Windows
# counts these together with *incoming* half-open connections, so the
# honeypot subtracts Noxis's own to spot stealth scans aimed at this machine.
_failed_connects = 0
_failed_lock = threading.Lock()


def note_failed_connect() -> None:
    global _failed_connects
    with _failed_lock:
        _failed_connects += 1


def failed_connects() -> int:
    with _failed_lock:
        return _failed_connects
