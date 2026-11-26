"""Run `noxis monitor` in the background, as a service.

Linux: a systemd service that starts at boot (after the network is up),
restarts if it crashes, and keeps running after you log out or close SSH.
It runs as you, not as root, with exactly two extra permissions:
CAP_NET_RAW (watch packets, to name stealth scanners and spot network
sweeps) and CAP_NET_BIND_SERVICE (decoys on ports below 1024). The
honeypot talks to whoever probes it, so it shouldn't run with more power
than it needs. Output goes to the system journal.

Windows: a Task Scheduler task that starts when you log on (or, with
--at-startup, when the computer starts), with no window. Output goes to
service.log in the Noxis data folder.

Pausing keeps the service installed but stopped, and it stays paused
across reboots until resumed. service.json remembers the options it was
installed with and whether it's paused, so push notifications can say
"paused" and "resumed" instead of "stopped" and "started".
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from .store import read_json, write_json

UNIT_NAME = "noxis.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME
TASK_NAME = "Noxis"
LOG_LIMIT = 5 * 1024 * 1024  # service.log is rotated (kept as service.log.old) past this

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = os.name == "nt"


class ServiceError(Exception):
    pass


def supported() -> str | None:
    """Why services aren't available here, or None."""
    if IS_LINUX or IS_WINDOWS:
        return None
    return "running Noxis as a service is supported on Linux and Windows only"


def _run(cmd: list[str], timeout: float = 30) -> tuple[int, str]:
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, **kwargs)
    except FileNotFoundError:
        return 127, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, f"{cmd[0]} timed out"
    return p.returncode, (p.stdout + p.stderr).decode(errors="replace").strip()


def _must(cmd: list[str]) -> str:
    code, out = _run(cmd)
    if code:
        raise ServiceError(f"`{' '.join(cmd)}` failed: {out or f'exit code {code}'}")
    return out


# ----------------------------------------------------------------- state


def state_path(root: Path) -> Path:
    return root / "service.json"


def read_state(root: Path) -> dict:
    data = read_json(state_path(root), {})
    return data if isinstance(data, dict) else {}


def write_state(root: Path, **changes) -> dict:
    data = {**read_state(root), **changes}
    write_json(state_path(root), data)
    return data


def take_event(root: Path) -> str | None:
    """'paused' or 'resumed' if the service was just paused/resumed (then cleared)."""
    event = read_state(root).get("event")
    if event == "resumed":
        write_state(root, event=None)
    return event


def stop_file(root: Path) -> Path:
    return root / "service.stop"


# A clean stop for Windows, which can only kill a task outright: `noxis
# service pause` creates service.stop, and `noxis service run` notices and
# sets this, so the monitor finishes its round and sends "paused".
STOP = threading.Event()


def watch_stop_file(root: Path) -> None:
    def loop():
        while not STOP.is_set():
            if stop_file(root).exists():
                try:
                    stop_file(root).unlink()
                except OSError:
                    pass
                STOP.set()
                return
            time.sleep(1)
    threading.Thread(target=loop, daemon=True, name="noxis-stopwatch").start()


# ----------------------------------------------------------------- Linux


def python_path() -> str:
    """Where the noxis package lives, so the service finds the same copy."""
    return str(Path(__file__).resolve().parent.parent)


def systemd_unit(user: str, home: Path, python: str, options: list[str]) -> str:
    cmd = " ".join(shlex.quote(a) for a in [python, "-m", "noxis", "monitor", *options])
    return f"""[Unit]
Description=Noxis network monitor
Documentation=https://github.com/SwadheenMishra/Noxis
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={user}
Environment=NOXIS_HOME={home}
Environment=PYTHONPATH={python_path()}
Environment=PYTHONUNBUFFERED=1
Environment=NOXIS_SERVICE=1
ExecStart={cmd}
Restart=on-failure
RestartSec=30
# Exactly what the honeypot needs, nothing more: watching packets (to name
# stealth scanners and spot network sweeps) and decoys on ports below 1024.
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
"""


def linux_service_user(explicit: str | None) -> str:
    """Who the service runs as: --user, or whoever ran sudo."""
    if explicit:
        return explicit
    user = os.environ.get("SUDO_USER")
    if user and user != "root":
        return user
    raise ServiceError("Noxis runs as a normal user, not root. Run this with sudo from your "
                       "own account, or name the account: --user NAME")


def linux_install(root: Path, options: list[str], user: str) -> None:
    UNIT_PATH.write_text(systemd_unit(user, root, sys.executable, options), encoding="utf-8")
    os.chmod(UNIT_PATH, 0o644)
    _must(["systemctl", "daemon-reload"])
    _must(["systemctl", "enable", UNIT_NAME])
    _must(["systemctl", "restart", UNIT_NAME])


def linux_installed() -> bool:
    return UNIT_PATH.exists()


def linux_status() -> dict:
    code, out = _run(["systemctl", "show", UNIT_NAME, "-p",
                      "ActiveState,SubState,UnitFileState,ActiveEnterTimestamp,MainPID,NRestarts"])
    info = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return {"running": info.get("ActiveState") == "active",
            "state": f"{info.get('ActiveState', '?')} ({info.get('SubState', '?')})",
            "starts_on_boot": info.get("UnitFileState") == "enabled",
            "since": info.get("ActiveEnterTimestamp") or None,
            "restarts": info.get("NRestarts")}


def can_read_journal() -> bool:
    """Root, and members of adm or systemd-journal, can read a system service's log."""
    if os.geteuid() == 0:
        return True
    import grp
    names = set()
    for gid in os.getgroups():
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return bool(names & {"adm", "systemd-journal"})


def linux_recent_log(lines: int = 12) -> list[str]:
    code, out = _run(["journalctl", "-u", UNIT_NAME, "-n", str(lines), "--no-pager", "-o", "cat"])
    return out.splitlines() if code == 0 and "No journal files" not in out else []


def linux_pause() -> None:
    _must(["systemctl", "disable", "--now", UNIT_NAME])


def linux_resume() -> None:
    _must(["systemctl", "enable", "--now", UNIT_NAME])


def linux_uninstall() -> None:
    _run(["systemctl", "disable", "--now", UNIT_NAME])
    try:
        UNIT_PATH.unlink()
    except FileNotFoundError:
        pass
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed", UNIT_NAME])


def sudo_argv(argv: list[str], root: Path) -> list[str]:
    """Re-run this command with sudo, keeping the same data folder."""
    return ["sudo", "env", f"NOXIS_HOME={root}", sys.executable, "-m", "noxis", *argv]


# ----------------------------------------------------------------- Windows


def pythonw() -> str:
    """pythonw.exe runs without a console window; fall back to python.exe."""
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    return str(w if w.exists() else exe)


def task_xml(root: Path, options: list[str], at_startup: bool, user: str) -> str:
    args = " ".join(_win_quote(a) for a in
                    ["-m", "noxis", "service", "run", f"--home={root}", "--", *options])
    if at_startup:
        trigger = "<BootTrigger><Enabled>true</Enabled><Delay>PT1M</Delay></BootTrigger>"
        logon = "Password"
    else:
        trigger = (f"<LogonTrigger><Enabled>true</Enabled><UserId>{escape(user)}</UserId>"
                   "<Delay>PT30S</Delay></LogonTrigger>")
        logon = "InteractiveToken"
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Noxis network monitor (noxis service)</Description>
  </RegistrationInfo>
  <Triggers>{trigger}</Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user)}</UserId>
      <LogonType>{logon}</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(pythonw())}</Command>
      <Arguments>{escape(args)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def _win_quote(arg: str) -> str:
    return subprocess.list2cmdline([arg])


def windows_user() -> str:
    domain, user = os.environ.get("USERDOMAIN"), os.environ.get("USERNAME", "")
    return f"{domain}\\{user}" if domain else user


def windows_install(root: Path, options: list[str], at_startup: bool) -> None:
    user = windows_user()
    with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as fh:
        fh.write(task_xml(root, options, at_startup, user).encode("utf-16"))
        xml = fh.name
    try:
        cmd = ["schtasks", "/Create", "/TN", TASK_NAME, "/XML", xml, "/F"]
        if at_startup:
            # Windows itself asks for your password: it needs it to run the task
            # while nobody is logged on. Noxis never sees it.
            cmd += ["/RU", user, "/RP", "*"]
            code = subprocess.call(cmd)
            if code:
                raise ServiceError("Windows didn't create the task (wrong password?)")
        else:
            _must(cmd)
    finally:
        os.unlink(xml)
    _run(["schtasks", "/Run", "/TN", TASK_NAME])


def _task_info() -> dict | None:
    ps = (f"$t=Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue; if($t){{"
          "$i=$t|Get-ScheduledTaskInfo; [pscustomobject]@{State=[string]$t.State;"
          "Last=if($i.LastRunTime){$i.LastRunTime.ToString('s')};Result=$i.LastTaskResult;"
          "Trigger=[string]$t.Triggers[0].CimClass.CimClassName}|ConvertTo-Json}")
    code, out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=30)
    try:
        return json.loads(out) if code == 0 and out else None
    except json.JSONDecodeError:
        return None


def windows_installed() -> bool:
    return _task_info() is not None


def windows_status() -> dict:
    info = _task_info() or {}
    state = info.get("State", "?")
    return {"running": state == "Running", "state": state,
            "starts_on_boot": state != "Disabled",
            "trigger": "computer start" if "Boot" in str(info.get("Trigger")) else "logon",
            "since": info.get("Last"), "restarts": None}


def _wait_stopped(timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if (_task_info() or {}).get("State") != "Running":
            return True
        time.sleep(2)
    return False


def windows_stop(root: Path, timeout: float = 120) -> bool:
    """Ask the running monitor to stop cleanly; force it after `timeout`.
    Returns False if it had to be forced."""
    if (_task_info() or {}).get("State") != "Running":
        return True
    stop_file(root).write_text("stop", encoding="utf-8")
    if _wait_stopped(timeout):
        return True
    _run(["schtasks", "/End", "/TN", TASK_NAME])
    return False


def windows_pause(root: Path) -> bool:
    _must(["schtasks", "/Change", "/TN", TASK_NAME, "/DISABLE"])
    return windows_stop(root)


def windows_resume(root: Path) -> None:
    try:
        stop_file(root).unlink()
    except FileNotFoundError:
        pass
    _must(["schtasks", "/Change", "/TN", TASK_NAME, "/ENABLE"])
    _must(["schtasks", "/Run", "/TN", TASK_NAME])


def windows_uninstall(root: Path) -> None:
    windows_stop(root, timeout=60)
    _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    try:
        stop_file(root).unlink()
    except FileNotFoundError:
        pass


# ----------------------------------------------------------------- logs


def log_path(root: Path) -> Path:
    return root / "service.log"


def open_log(root: Path):
    """service.log for a Windows service run, rotated when it gets big."""
    path = log_path(root)
    try:
        if path.stat().st_size > LOG_LIMIT:
            path.replace(path.with_suffix(".log.old"))
    except OSError:
        pass
    fh = open(path, "a", encoding="utf-8", buffering=1)
    fh.write(f"\n===== service start {datetime.now():%Y-%m-%d %H:%M:%S} =====\n")
    return fh


def tail(path: Path, lines: int = 12) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
    except OSError:
        return []


def follow(path: Path) -> None:
    """Print new lines as they're written (Ctrl+C to stop)."""
    for line in tail(path, 20):
        print(line)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if line:
                    print(line, end="")
                else:
                    time.sleep(0.5)
    except FileNotFoundError:
        print(f"No log yet at {path}")
