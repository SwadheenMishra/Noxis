"""Push notifications: alerts sent to your phone (or any device) through ntfy.

ntfy (https://ntfy.sh) is free and open source. Use the public ntfy.sh server,
or run your own (for example on the same Pi as Noxis) so alerts never leave
your network. Alerts whose preset level is `push` are sent here, plus
optional start/stop messages and a scheduled summary.

Sending never slows the monitor down: it happens in a background thread.
The first alert goes out at once; alerts that follow within BUNDLE seconds
are sent together as one message. If the server can't be reached, messages
wait and are retried, then delivered together once it's back.

Settings, including access tokens, are in push.json in the Noxis data
folder, readable only by you on Linux and macOS.
"""

from __future__ import annotations

import json
import os
import queue
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from .store import read_json, write_json

PUBLIC_SERVER = "https://ntfy.sh"
TOPIC_RE = re.compile(r"[-_A-Za-z0-9]{1,64}")
BUNDLE = 30  # seconds: alerts this close together become one message
MAX_BACKLOG = 100  # messages kept while the server is unreachable
RETRY = [30, 60, 120, 300]  # seconds between retries, then every 5 min
MAX_BODY = 3900  # ntfy allows 4096 bytes


class PushError(Exception):
    pass


def new_topic() -> str:
    """A random topic name. On a public server the topic is the password:
    anyone who knows it can read your alerts, so it must be unguessable."""
    return "noxis-" + secrets.token_urlsafe(18)  # letters, digits, - and _


def is_public(server: str) -> bool:
    return (urlparse(server).hostname or "").lower() == "ntfy.sh"


def detail_for(channel: dict) -> str:
    """'full' or 'minimal'. Your own server gets the whole alert; the public
    ntfy.sh gets only what kind of alert it was, unless you choose otherwise."""
    mode = channel.get("detail", "auto")
    if mode in ("full", "minimal"):
        return mode
    return "minimal" if is_public(channel.get("server", PUBLIC_SERVER)) else "full"


def describe_channel(ch: dict) -> str:
    auth = ", token" if ch.get("token") else ""
    return f"ntfy {ch['server'].rstrip('/')}/{ch['topic']}  ({detail_for(ch)} messages{auth})"


# ------------------------------------------------------------------ messages


@dataclass
class Message:
    title: str
    body: str
    minimal: str  # what a 'minimal' channel gets instead of the body
    priority: int = 3  # ntfy: 1 min, 3 default, 4 high, 5 urgent
    tags: list[str] = field(default_factory=list)
    when: float = field(default_factory=time.time)
    status: bool = False  # about Noxis itself (started, stopped, summary): never bundled


def host_name() -> str:
    return socket.gethostname() or "this machine"


SEVERITY_PRIORITY = {"high": 5, "medium": 4}
KIND = {"honeypot": "Honeypot", "network-sweep": "Network sweep", "lure-visit": "Lure",
        "new-device": "New device"}


def alert_message(alert, where: str, host: str | None = None) -> Message:
    host = host or host_name()
    kind = KIND.get(alert.rule) or alert.rule.split("-")[0].capitalize()
    body = alert.text + (f"\n{alert.detail}" if alert.detail else "") + f"\n({where}, seen by {host})"
    return Message(
        title=f"Noxis: {alert.title}"[:120],
        body=body,
        minimal=f"{kind} alert on {host}. Details are in alerts.log there.",
        priority=SEVERITY_PRIORITY.get(alert.severity, 3),
        tags=["rotating_light" if alert.severity == "high" else "warning"])


def status_message(title: str, body: str, minimal: str) -> Message:
    return Message(title=title, body=body, minimal=minimal, priority=2, tags=["owl"], status=True)


def combine(msgs: list[Message], late: bool = False) -> tuple[str, str, str, int, list[str]]:
    """(title, full body, minimal body, priority, tags) for one or more messages."""
    prio = max(m.priority for m in msgs)
    tags = list(dict.fromkeys(t for m in msgs for t in m.tags))
    note = "Couldn't be sent earlier (network or server was down):\n" if late else ""
    if len(msgs) == 1:
        m = msgs[0]
        stamp = f"[{datetime.fromtimestamp(m.when):%H:%M}] " if late else ""
        return m.title, note + stamp + m.body, note + m.minimal, prio, tags
    title = f"Noxis: {len(msgs)} alerts"
    full = note + "\n\n".join(f"[{datetime.fromtimestamp(m.when):%H:%M:%S}] {m.body}" for m in msgs)
    minimal = note + "\n".join(dict.fromkeys(m.minimal for m in msgs))
    return title, full, minimal, prio, tags


def send_ntfy(channel: dict, title: str, body: str, priority: int, tags: list[str],
              timeout: float = 10) -> None:
    """Publish one message. JSON publishing keeps non-English text intact
    (HTTP headers can't always carry it)."""
    from . import __version__
    if len(body.encode()) > MAX_BODY:
        body = body.encode()[:MAX_BODY].decode(errors="ignore") + "\n..."
    payload = {"topic": channel["topic"], "title": title, "message": body,
               "priority": priority, "tags": tags}
    headers = {"Content-Type": "application/json", "User-Agent": f"noxis/{__version__}"}
    if channel.get("token"):
        headers["Authorization"] = f"Bearer {channel['token']}"
    req = urllib.request.Request(channel["server"].rstrip("/") + "/", data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(2048)
    except urllib.error.HTTPError as e:
        if channel.get("token"):
            denied = (f"this access token isn't allowed to post to '{channel['topic']}' "
                      "(check the token's user has write access to that topic)")
        else:
            denied = (f"the server doesn't let anyone without a login post to '{channel['topic']}'. "
                      "Add an access token (--token), or give that topic write access on the server")
        why = {401: "the server wants a login: add an access token (--token)",
               403: denied,
               429: "the server's rate limit was reached",
               507: "the server's daily message limit was reached"}.get(e.code, e.reason)
        raise PushError(f"HTTP {e.code}: {why}") from None
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise PushError(f"couldn't reach {channel['server']} ({reason})") from None


# ------------------------------------------------------------------ settings


class PushConfig:
    def __init__(self, root: Path):
        self.path = root / "push.json"
        data = read_json(self.path, {})
        data = data if isinstance(data, dict) else {}
        self.channels: list[dict] = data.get("channels", [])
        self.startstop: bool = data.get("startstop", True)
        self.summary: dict | None = data.get("summary")  # {"at": "09:00"} or {"every": 6}

    def save(self) -> None:
        write_json(self.path, {"channels": self.channels, "startstop": self.startstop,
                               "summary": self.summary})
        try:
            os.chmod(self.path, 0o600)  # it can hold access tokens
        except OSError:
            pass

    def add_ntfy(self, topic: str | None, server: str | None, token: str | None,
                 detail: str = "auto") -> dict:
        server = (server or PUBLIC_SERVER).rstrip("/")
        if "://" not in server:
            server = "https://" + server
        if not urlparse(server).hostname:
            raise ValueError(f"'{server}' isn't a server address, e.g. https://ntfy.example.com")
        topic = topic or new_topic()
        if not TOPIC_RE.fullmatch(topic):
            raise ValueError("Topic names use letters, digits, - and _ (up to 64 characters).")
        ch = {"type": "ntfy", "server": server, "topic": topic, "detail": detail}
        if token:
            ch["token"] = token
        self.channels.append(ch)
        return ch


SCHEDULE_HELP = ("Give a daily time like 09:00, an interval like 'every 6h' (1-24), fixed times "
                 "like 'every 12h from 21:00', or 'off'.")


def _clock(text: str) -> str | None:
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", text)
    if m and int(m[1]) < 24 and int(m[2]) < 60:
        return f"{int(m[1]):02d}:{m[2]}"
    return None


def parse_summary(text: str) -> dict | None:
    """'09:00'                -> daily at 09:00
    'every 6h' / '6h'      -> every 6 hours, counted from when Noxis started
    'every 12h from 21:00' -> at fixed times: 21:00 and 09:00
    'off'                  -> none"""
    text = " ".join(text.strip().lower().split())
    if text == "off":
        return None
    if at := _clock(text):
        return {"at": at}
    m = re.fullmatch(r"(?:every )?(\d{1,2}) ?h(?:ours?)?(?: from (\S+))?", text)
    if not m or not 1 <= int(m[1]) <= 24:
        raise ValueError(SCHEDULE_HELP)
    hours = int(m[1])
    if m[2] is None:
        return {"every": hours}
    start = _clock(m[2])
    if start is None:
        raise ValueError(SCHEDULE_HELP)
    if 24 % hours:
        # Otherwise the times shift every day, and a missing summary is hard to spot.
        raise ValueError("With 'from', the interval must fit the day evenly: "
                         "1, 2, 3, 4, 6, 8, 12 or 24 hours.")
    return {"at": start} if hours == 24 else {"every": hours, "from": start}


def summary_times(spec: dict) -> list[str]:
    """The fixed clock times of a schedule, earliest first ([] if relative)."""
    if "at" in spec:
        return [spec["at"]]
    if "from" not in spec:
        return []
    h, m = map(int, spec["from"].split(":"))
    return sorted(f"{(h + k * spec['every']) % 24:02d}:{m:02d}" for k in range(24 // spec["every"]))


def describe_summary(spec: dict | None) -> str:
    if not spec:
        return "off"
    if "at" in spec:
        return f"daily at {spec['at']}"
    if "from" in spec:
        times = summary_times(spec)
        shown = ", ".join(times) if len(times) <= 6 else f"{times[0]}, {times[1]}, ..."
        return f"every {spec['every']}h from {spec['from']} ({shown})"
    return f"every {spec['every']}h"


def _last_slot(spec: dict, now: datetime) -> datetime:
    """The most recent scheduled time at or before `now`."""
    start = spec.get("at") or spec["from"]
    every = timedelta(hours=spec.get("every", 24))
    h, m = map(int, start.split(":"))
    anchor = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if anchor > now:
        anchor -= timedelta(days=1)
    return anchor + ((now - anchor) // every) * every


def summary_due(spec: dict | None, last: datetime | None, started: datetime, now: datetime) -> bool:
    """Whether a summary should go out now. A fixed time that was missed by
    more than an hour (Noxis wasn't running then) is skipped, not sent late:
    the missing summary is itself the signal that something was wrong."""
    if not spec:
        return False
    if "at" not in spec and "from" not in spec:
        return now - (last or started) >= timedelta(hours=spec["every"])
    slot = _last_slot(spec, now)
    return (last is None or last < slot) and now - slot < timedelta(hours=1)


# ------------------------------------------------------------------ sender


class Pusher:
    """Background sender for all configured channels."""

    def __init__(self, channels: list[dict], sender=None, bundle: float = BUNDLE,
                 retry: list[float] | None = None):
        self.channels = channels
        self.sender = sender
        self.bundle = bundle
        self.retry = retry or RETRY
        self.queue: queue.Queue = queue.Queue()
        self.backlog: dict[int, list[Message]] = {i: [] for i in range(len(channels))}
        self.dropped = 0
        self.failures = 0  # consecutive
        self.last_error: str | None = None
        self.sent = 0
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def send(self, msg: Message) -> None:
        with self._lock:
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, daemon=True, name="noxis-push")
                self._thread.start()
        self.queue.put(msg)

    def close(self, timeout: float = 15) -> None:
        """Send what's waiting (no bundling delay), then stop."""
        if self._thread is not None:
            self.queue.put(None)
            self._thread.join(timeout)

    def pending(self) -> int:
        return max((len(b) for b in self.backlog.values()), default=0)

    def _run(self) -> None:
        stopping = False
        while not stopping:
            wait = None
            if self.pending():
                wait = self.retry[min(self.failures, len(self.retry)) - 1] if self.failures else 1
            try:
                first = self.queue.get(timeout=wait)
            except queue.Empty:
                self._deliver([])  # retry the backlog
                continue
            if first is None:
                self._deliver([])
                return
            self._deliver([first])
            if first.status:
                continue  # started/stopped/summary: no bundling window after it
            # Alerts arriving soon after go out together. Status messages
            # still go on their own, after the alerts that came before them.
            batch: list[Message] = []
            deadline = time.monotonic() + self.bundle
            while (left := deadline - time.monotonic()) > 0:
                try:
                    item = self.queue.get(timeout=left)
                except queue.Empty:
                    break
                if item is None:
                    stopping = True
                    break
                if item.status:
                    if batch:
                        self._deliver(batch)
                        batch = []
                    self._deliver([item])
                    continue
                batch.append(item)
            if batch:
                self._deliver(batch)
        self._deliver([])

    def _try(self, ch: dict, msgs: list[Message], late: bool) -> bool:
        title, full, minimal, prio, tags = combine(msgs, late=late)
        try:
            (self.sender or send_ntfy)(ch, title, minimal if detail_for(ch) == "minimal" else full,
                                       prio, tags)
        except PushError as e:
            self.last_error = str(e)
            return False
        self.sent += 1
        return True

    def _keep(self, i: int, msgs: list[Message]) -> None:
        waiting = self.backlog[i] + msgs
        self.dropped += max(0, len(waiting) - MAX_BACKLOG)
        self.backlog[i] = waiting[-MAX_BACKLOG:]

    def _deliver(self, new: list[Message]) -> None:
        for i, ch in enumerate(self.channels):
            if self.backlog[i]:
                if not self._try(ch, self.backlog[i], late=True):
                    self._keep(i, new)  # still down: new ones wait too, in order
                    continue
                self.backlog[i] = []
            if new and not self._try(ch, new, late=False):
                self._keep(i, new)
        self.failures = self.failures + 1 if self.pending() else 0


def test_channel(channel: dict, sender=None) -> str | None:
    """Send a test message right away. Returns an error, or None if it worked."""
    try:
        (sender or send_ntfy)(channel, "Noxis test", f"Push notifications from {host_name()} work.",
                              3, ["owl"])
    except PushError as e:
        return str(e)
    return None
