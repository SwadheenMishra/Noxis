# Noxis

*Your network's night watch.*

**A network security scanner for the networks you actually use: home Wi-Fi, a
rental, a hotel.**

Noxis finds every device on the network you're connected to and works out what
each one is: router, laptop, iPhone, Wi-Fi camera, ESP32 board, Raspberry Pi and
so on. It flags the ones that shouldn't be there and checks whether anyone is
tampering with your connection. Then it keeps watching.

- **Hidden cameras**, on the network or broadcasting their own hotspot nearby
- **Unidentified microcontrollers and drop boxes** (ESP32, Raspberry Pi)
- **Evil-twin Wi-Fi**: networks copying your network's name
- **ARP spoofing**, MAC cloning and router impersonation
- **HTTPS interception, DNS hijacking and injected web pages**
- **Port scans, stealth scans included,** caught by a built-in honeypot
- **Risky open services**: Telnet, ADB, exposed databases and camera streams
- **Router port forwards** that devices opened to the internet by themselves (UPnP)
- **What every device is hosting**: web apps, media servers, file shares and proxies,
  including fake login pages and interception tools

It's pure Python with **no dependencies** and **no admin rights needed**. It
runs on Windows, Linux and macOS.

For 24/7 monitoring, run it on any machine that stays on: a homelab server, an
old PC, a laptop or a Raspberry Pi. **Linux is recommended for monitoring.**
Running as root there, Noxis can name the device behind a stealth scan and spot
devices mapping your network, which it can't do on Windows. A Raspberry Pi is a
good choice for running it long-term because it uses very little power, but
any old machine works.

> **Status:** early development (0.1). Expect rough edges, and only scan
> networks you're allowed to.

## Quick start

```powershell
git clone <this repo>
cd Noxis
pip install -e .          # installs the `noxis` command (or use `python -m noxis`)

noxis update-oui         # once: download the IEEE manufacturer list (~5 MB)
noxis scan --open        # scan and open the HTML report
noxis trust --all        # after checking every device is yours
noxis monitor --notify   # keep watching (on any machine that stays on)
```

Somewhere unfamiliar, such as an Airbnb or hotel:

```powershell
noxis sweep --honeypot --open
```

## Choosing a mode

| Mode | Use it when | What it does | Takes | Leaves you |
|---|---|---|---|---|
| `scan` | You want a snapshot of a network right now: your home, or a quick first look anywhere | One pass: finds devices, identifies them and their services, checks nearby Wi-Fi and your connection | ~40 s | A terminal summary and an HTML report |
| `sweep` | You're somewhere you don't trust, such as an Airbnb, hotel or office, and want a thorough check before relaxing | Several scans spaced apart, merged into one report. Devices that sleep (battery cameras, phones) get more chances to show up. Adds a physical-search checklist | ~6 min by default | A timestamped HTML report you can keep as evidence |
| `monitor` | You want to keep watch over a network, for hours or 24/7 | Scans again every few minutes and alerts on what your [alert preset](#alerts) cares about: a new device joining, something high-risk appearing, someone touching the honeypot. Remembers what it has seen across restarts. Runs until you stop it | Until stopped | Alerts on screen, in `alerts.log` and, with `--notify`, as desktop pop-ups |
| `check` | You've just joined a network and only want to know whether it's tampering with your connection | Only the connection checks: HTTPS interception, DNS, page tampering and router port forwards. No device scan | ~5-10 s | A pass/fail list (exit code 1 if anything is high) |
| `honeypot` | You want to know whether anyone is probing this computer, without scanning anything yourself | Runs fake services (Telnet, FTP, SSH, databases...) and alerts on anyone who touches them | Until stopped | Alerts and `honeypot.log` |

`noxis` on its own is the same as `noxis scan`.

**`scan` vs `sweep`:** a scan is one look. A sweep is several looks over a few
minutes, which matters because many cameras and battery devices sleep and only
wake up to upload. In a place you don't trust, always sweep.

**`sweep` vs `monitor`:** a sweep has an end and produces a report; you run it
when you arrive somewhere. Monitor never ends and produces alerts; you run it on
a network you stay on. Monitor works on any machine that stays on (a homelab
server, an old PC, a laptop or a Raspberry Pi), so a new device joining your
home network at 3 a.m. is flagged within minutes.

```powershell
noxis scan --open                           # what's on this network right now?
noxis sweep --honeypot --open               # just arrived at a rental
noxis sweep --rounds 10 --wait 60 --deep    # a long, thorough sweep
noxis monitor --honeypot --deep --notify    # keep watch on your home network
noxis check                                 # is this cafe Wi-Fi tampering with me?
```

## Flags

Which modes accept which flag. "-" means the flag doesn't apply to that mode.

| Flag | What it does | `scan` | `sweep` | `monitor` | `honeypot` |
|---|---|:-:|:-:|:-:|:-:|
| `--target CIDR` | Scan this network instead of the one you're on, e.g. `192.168.1.0/24`. Private ranges only, up to 1024 addresses | ✓ | ✓ | ✓ | - |
| `--quick` | Check 13 key ports per device instead of 70. Faster, but identifies fewer services | ✓ | ✓ | ✓ | - |
| `--no-wifi` | Skip the nearby Wi-Fi check (camera hotspots, evil twins). For machines without Wi-Fi | ✓ | ✓ | ✓ | - |
| `--no-checks` | Skip the HTTPS, DNS and page-tampering checks, which need internet. The router port-forward check still runs | ✓ | ✓ | ✓ | - |
| `--deep [IP ...]` | Check all 65,535 ports to find services on unusual ports. Alone: every device. With IPs: only those. A few minutes per device. In `sweep` and `monitor`, each device is deep-scanned once: in the first round, or when it first appears | ✓ | ✓ | ✓ | - |
| `--deep-connections N` | With `--deep`: ports tried at once per device, 1-200 (default 200). Lower is gentler and slower: ~4 min per device at 200, ~8 at 100, ~16 at 50 | ✓ | ✓ | ✓ | - |
| `--open` | Open the HTML report in your browser when done | ✓ | ✓ | - | - |
| `--no-html` | Don't write an HTML report | ✓ | - | - | - |
| `--json PATH` | Also save the results as JSON | ✓ | - | - | - |
| `--rounds N` | How many scans the sweep runs (default 4) | - | ✓ | - | - |
| `--wait SECONDS` | Pause between sweep rounds (default 30) | - | ✓ | - | - |
| `--interval SECONDS` | Pause between monitor scans (default 300) | - | - | ✓ | - |
| `--preset NAME` | Use this [alert preset](#alerts) for the whole run, instead of each network's own | - | - | ✓ | - |
| `--remind HOURS` | Alert again about a problem that's still there after this many hours (default: never) | - | - | ✓ | - |
| `--honeypot` | Also run the decoy services, for as long as the sweep or monitor runs. Sweep hits go in the report | - | ✓ | ✓ | always on |
| `--lure` | Also run a fake web login on port 80 so casual scanners can see this computer and walk into the decoys. Turns the honeypot on. You're invisible again when Noxis stops | - | ✓ | ✓ | ✓ |
| `--ports 23,2323,...` | Choose which decoy ports the honeypot opens | - | ✓ | ✓ | ✓ |
| `--bind ADDRESS` | Address the decoys listen on (`127.0.0.1` to test on this computer only) | - | - | - | ✓ |
| `--notify` | Desktop pop-up for each alert. Windows, and Linux with a desktop (needs `notify-send`: `sudo apt install libnotify-bin`). Works under `sudo` too. Not on a machine you only reach over SSH | - | ✓ * | ✓ | ✓ |
| `--beep` | Terminal beep for each alert, on any OS. Over SSH, the beep plays on the computer you're connecting from. Needs the terminal's bell turned on | - | ✓ * | ✓ | ✓ |

\* In a sweep, `--notify` and `--beep` fire for honeypot alerts as they happen;
everything else is in the report at the end. The same goes for [push
notifications](#push-notifications), which need no flag: once set up, they're on
for `monitor`, `honeypot` and `sweep --honeypot`.

`check`, `known` and `update-oui` take no flags. `alerts` and `mute` are described under [Alerts](#alerts), `push` under [Push notifications](#push-notifications).

## Trust

Noxis flags what it doesn't recognise. Once you've checked that a network's
devices are yours, trust them, and from then on only changes stand out.

| Command | What it does |
|---|---|
| `trust --all` | Trusts every device in the last scan, with a fingerprint of each (type, ports, services). Also saves this network's access points and DNS servers, so evil twins and DNS changes stand out |
| `trust <ip/mac/name> [--name "..."]` | Trusts one device, optionally with a nickname, e.g. `noxis trust 192.168.1.30 --name "My iPhone"` |
| `trust <ip>:<port> [--name "..."]` | Trusts one service, optionally with a nickname, e.g. `noxis trust 192.168.1.70:8080 --name "Landing page"` |
| `forget <ip/mac/name>` | Removes a device from the trusted list |
| `known` | Lists trusted devices for every network |
| `update-oui` | Downloads the full IEEE manufacturer list (run once, ~5 MB) |

Trust is per network: trusting your home devices doesn't make them trusted on a
hotel's Wi-Fi. Trusting works on the most recent `scan`, `sweep` or `monitor`
round, so run one first. A running monitor picks up `trust` and `forget`
straight away; there's no need to restart it.

## Alerts

`monitor` and the honeypot don't alert on everything they find, because what's
worth an alert depends on where you are. On your home network, a new device
joining is news. In a hotel, other guests' devices are normal. So Noxis uses an
**alert preset**: a list saying how loudly to report each kind of problem.

**Most people don't need to change anything.** Two presets are built in, and
Noxis picks one for each network:

| | `home` | `travel` |
|---|---|---|
| **Used on** | Networks where you've trusted devices | Every other network |
| A new device joins | Alert | Ignored |
| High-risk problem (camera, evil twin, connection tampering...) | Alert | Alert |
| Medium problem (untrusted device, DNS server changed...) | Logged only | Logged only |
| Someone touches or scans the honeypot | Push | Push |
| A device maps every address on the network | Push | Alert |

> **Tip:** run `noxis trust --all` on your home network before you start
> monitoring it. Until you've trusted at least one device there, Noxis treats
> it like a hotel and won't tell you about new devices.

What each level means:

| Level | What happens |
|---|---|
| `off` | Nothing |
| `log` | Written to `alerts.log`, nothing on screen |
| `alert` | Shown on screen and written to `alerts.log`, with `--beep` and `--notify` if you turned them on |
| `push` | Same as `alert`, and also sent to your phone or any other device, if you've set up [push notifications](#push-notifications) |

### Changing what alerts you

The built-in presets can't be edited. Make your own copy and change that:

```powershell
noxis alerts                                    # which preset this network uses
noxis alerts show home                          # what each kind of alert is set to
noxis alerts new myhome --from home             # make your own copy
noxis alerts set myhome network-medium alert    # e.g. alert on medium network problems, like a DNS change
noxis alerts use myhome                         # use it on this network
```

"This network" means the network of your most recent scan, the same as for
`noxis trust`. A few more options:

- `noxis alerts rules` lists every kind of alert you can set.
- You can also set one specific problem by its name, e.g.
  `noxis alerts set myhome dns-server-changed push`. Every line in `alerts.log`
  shows both names in brackets, e.g. `[network-medium | dns-server-changed]`: the
  first is the general kind, the second the exact problem. Either one works.
- `noxis alerts use myhome --default untrusted` uses it on every network you
  haven't trusted any devices on. Use `--default trusted` for the others.
- `noxis alerts use auto` lets Noxis pick for this network again.
- `noxis monitor --preset myhome` uses it for one run only.

### Muting one alert

If something keeps alerting and you've checked that it's fine, mute it. Muted
alerts are still written to `alerts.log`, marked as muted, so nothing is hidden.
They just stop interrupting you. A mute can be narrowed down so it only covers
exactly what you checked:

```powershell
noxis mute add network-sweep --from 192.168.1.1 --between 02:00-03:00 --note "router's nightly check"
noxis mute list
noxis mute remove 1
```

| Option | Only mutes it... |
|---|---|
| `--from IP_OR_MAC` | when it comes from this device |
| `--network this` | on this network (the most recent scan's) |
| `--between 02:00-03:00` | in this daily time window (can cross midnight, e.g. `23:00-01:00`) |
| `--note "..."` | (doesn't limit anything: a reminder of why, shown in `mute list`) |

### How the monitor avoids repeating itself

- You're told about a problem **once**, when it appears, not every round.
- If it goes away (missing for 3 rounds in a row) and later comes back, you're
  told again.
- A device that's switched off or asleep doesn't count as fixed. A camera that
  sleeps between rounds won't alert every time it wakes up.
- `--remind 12` repeats problems that still aren't fixed, every 12 hours.
- The monitor remembers all this across restarts and reboots. Restarting it
  doesn't repeat old alerts, and a device that joined while it was off is still
  reported.
- Each network is remembered separately, so taking a laptop to a cafe doesn't
  flag every device there as new.
- Changes from `noxis trust`, `noxis alerts` and `noxis mute` apply to a monitor
  that's already running. No restart needed.

## Push notifications

Alerts set to `push` can reach your phone, or any other device, through
[ntfy](https://ntfy.sh): free, open source, with apps for Android and iPhone.
You can use the public ntfy.sh server, or run your own (on the same Pi as Noxis,
for example) so alerts never leave your network.

```powershell
noxis push add ntfy     # uses ntfy.sh with a new random topic, and prints it
noxis push test         # sends a test message: check your phone
```

Then install the ntfy app and subscribe to the topic Noxis printed. That's it:
from now on, `monitor`, `honeypot` and `sweep --honeypot` send their `push`
alerts there.

**What gets sent:**

| Server | Messages | Example |
|---|---|---|
| Public ntfy.sh | **Minimal**: only what kind of alert, nothing about your network | "Honeypot alert on pi5. Details are in alerts.log there." |
| Your own server | **Full**: the whole alert | "Port scan detected from 192.168.1.45 (Hikvision, untrusted ...)" |

Add `--full` or `--minimal` to choose for yourself. On ntfy.sh, the topic name is
the password: anyone who knows it can read your messages. That's why Noxis makes a
long random one; keep it private.

**Your own ntfy server**, for example on the Pi, reached through Tailscale when
you're away from home:

```powershell
noxis push add ntfy --server https://your-pi.your-tailnet.ts.net
noxis push add ntfy my-topic --server https://ntfy.example.com --token tk_...   # if it needs a login
```

**On an iPhone**, notifications from your own server only show up when you open
the ntfy app, unless the server's `server.yml` has these lines:

```yaml
base-url: "http://your-pi.your-tailnet.ts.net:2586"   # exactly the address you use in the app
upstream-base-url: "https://ntfy.sh"
listen-http: ":2586"                                   # keep the port your address uses
```

That's how Apple works: only its own push service can wake an iPhone. With this
setting your server sends ntfy.sh only a "new message" signal with a message ID,
never the alert itself; the phone then fetches the alert from your server.
`base-url` must match the app's address character for character (including
`http://` and the port), or the wake-up goes nowhere. After changing it, restart
ntfy (`sudo systemctl restart ntfy`), then unsubscribe and subscribe again in the
app. Check that `sudo journalctl -u ntfy -n 3` says it's listening on the port
you expect: if `listen-http` is missing, ntfy falls back to port 80.

**Messages about Noxis itself:**

| Command | Sends |
|---|---|
| `noxis push startstop on` / `off` | A message when `monitor` or `honeypot` starts and stops (on by default). If Noxis crashes, the message says so with high priority. After a power cut, you'll see "started" with no "stopped" before it |
| `noxis push summary 09:00` | A daily "still watching" summary: how many scans and alerts, how many devices, and when Noxis last restarted |
| `noxis push summary every 12h from 21:00` | At fixed times: here 21:00 and 09:00. The hours must fit the day evenly (1, 2, 3, 4, 6, 8, 12) |
| `noxis push summary every 6h` | Every 6 hours (1-24), counted from when Noxis started |
| `noxis push summary off` | No summaries (the default) |

The summary doubles as a check that Noxis is alive. **If it doesn't arrive when
it should, something is wrong**: the machine is off, Noxis stopped, or the
network or ntfy server is down. No second machine needed.

**When the server can't be reached,** alerts aren't lost: Noxis keeps up to 100,
retries, and sends them together, marked as late, once it's back. Alerts that
come within 30 seconds of each other are sent as one message, so a scan that
trips several alarms buzzes your phone once. The public ntfy.sh allows 250
messages a day.

`noxis push list` shows where messages go, and `noxis push remove 1` removes one.
Settings, including access tokens, are in `push.json`, readable only by you on
Linux and macOS.

## How it identifies devices

| Clue | Example |
|---|---|
| MAC manufacturer | `A0:DD:6C` is Espressif (ESP32); `44:19:B6` is Hikvision |
| Private MAC bit | `02:...` is a phone or tablet using a "private Wi-Fi address" |
| Open ports | 62078 is an iPhone or iPad; 554 is an RTSP camera stream; 34567/37777 are cheap DVRs |
| ONVIF (WS-Discovery) | IP cameras answer this camera-discovery probe |
| mDNS / Bonjour | `_googlecast`, `_esphomelib`, `_airplay`, `_printer`... |
| UPnP / SSDP | Manufacturer and model from the device description |
| HTTP / RTSP / SSH banners | Page titles like "NETSurveillance WEB", `Server: uc-httpd`, `Raspbian` |
| NetBIOS / reverse DNS | `DESKTOP-ABC123`, `iPhone.lan`, `esp32-cam.local` |

Each clue adds points to a device type. The highest score wins, and the report
shows the evidence and how sure Noxis is.

## What gets flagged

- **High:**
  - cameras and video recorders, and hacking tools (WiFi Pineapple, Kali hosts)
  - Telnet, network ADB and backdoor ports
  - ARP spoofing and a changed router MAC
  - camera-style hotspots nearby, and an open network copying yours
  - a trusted device that suddenly looks like a different kind of device (a cloned MAC)
  - HTTPS interception by unknown or attacker tools, and banking sites resolving to a local device
  - dangerous ports (Telnet, RDP, cameras, databases) forwarded to the internet, and any forward to a camera or unknown device
  - anyone scanning this computer
  - fake login pages imitating Google, Microsoft, banks or Wi-Fi portals (ESP32 "evil portals"),
    traffic-interception tools (mitmproxy, Burp, Bettercap) and an open Docker API
- **Medium:**
  - unidentified ESP32/Arduino boards and Raspberry Pi-style boxes
  - open camera streams, untrusted devices, and new ports on trusted devices
  - DNS pointed at an unexpected device, injected web pages, and antivirus or corporate HTTPS inspection
  - ports forwarded to untrusted devices, or to a device that didn't answer the scan
  - open proxies and DNS servers on untrusted devices, new services on trusted devices, and a
    trusted service that changed identity
- **Low:** devices that couldn't be identified, FTP/RDP/VNC exposure, unrecognised DNS servers,
  UPnP being on, and ports forwarded to trusted devices.

## Connection integrity

| Check | Catches |
|---|---|
| HTTPS interception | Certificates for major sites must come from public certificate authorities. Antivirus and corporate filters are named; mitmproxy, Burp, Fiddler and unknown roots are flagged high. |
| DNS server | Which DNS server you were told to use, with its name (often your ISP's, e.g. `dns1.yourisp.com`). `trust --all` remembers the servers, and Noxis warns (medium) if they change to an unknown server, which is how DNSChanger-style malware, hijacked routers and rogue DHCP servers redirect browsing. |
| Fake-domain test | A random nonexistent domain must not resolve (DNS hijacking, ISP ad redirection). |
| DNS answers | PayPal, Google, Microsoft and Apple must not resolve to local addresses (fake login pages). |
| HTTP tampering | A fixed test page must arrive unmodified (captive portals, injected scripts). |
| Router port forwards | Reads the forwards devices opened on the router through UPnP (read-only). Telnet, RDP, camera streams, databases and other dangerous ports, and anything forwarded to a camera, microcontroller or unknown device, are high. Forwards to untrusted devices are medium, and forwards to trusted devices are low. If your ISP shares your internet address (CGNAT), forwards can't be reached from outside, so everything drops one level. UPnP being on at all is low. |

UPnP lets any program ask the router to open a port to the internet, with no
password. Forwards you typed into the router's settings page usually aren't in
that list, because they need the router password to read, and NAT-PMP/PCP
forwards can't be listed (Noxis tells you if the router accepts them).

## Services

Every open port is identified from what it says about itself (page titles,
server headers, SSH/FTP banners), not just its number. Noxis recognises
Jellyfin, Plex, Home Assistant, Pi-hole, Portainer, Proxmox, Syncthing,
Nextcloud, databases, file shares, printers, cameras and more. A web server
with no title on a port only one app uses is shown as "Probably Jellyfin".

```
Services
  192.168.1.70  pi5
    22     SSH (OpenSSH 10.0p2)
    8080   Landing page (trusted)
  192.168.1.1  Router / gateway
    53     DNS server
    80     Web server (Boa/0.93.15) (redirects to /admin/login.asp)
```

Trusted services are remembered by a version-free fingerprint. A software
update doesn't raise an alert, but a different app on the same port does: your
landing page turning into a login form is "Trusted service changed". Proxies are
checked with a SOCKS greeting only, so Noxis never relays traffic through them.

`--deep` checks every port, to find services hiding on unusual ones. It takes
about 4 minutes for a Raspberry Pi on Wi-Fi, and longer for devices behind a
firewall. In `sweep` and `monitor`, each device is deep-scanned **once per run**:
every device in the first round, then any device the first time it shows up, so
a camera that was asleep in round 1 still gets its full check when it wakes.
Ports a deep scan found are re-checked in every later round, which takes a
second. On an always-on machine running `monitor --deep`, every new device on your network gets
a full port check within minutes of joining.

By default a deep scan tries 200 ports at a time per device. Use
`--deep-connections N` (1 to 200) to go gentler, for example on a network full of
cheap cameras or battery devices: about 8 minutes per device at 100, and 16 at 50.
A device that drops off the network during a deep scan is usually on a weak
power supply rather than overloaded by the scan.

## Honeypot

Decoy services (fake Telnet, FTP, SSH, MySQL, Redis, VNC, ADB and others) that
nothing legitimate ever touches.

| Alert | Means | Where |
|---|---|---|
| Connection to decoy *service* | Someone probed a fake service. What they typed is logged. | All |
| Port scan hit the honeypot | 3+ decoys touched within 2 minutes | All |
| Stealth port scan detected | Half-open probes (nmap's default mode as admin/root, masscan), read from TCP counters. The sender isn't known. | Windows |
| Port scan detected | 10+ ports in 15s at packet level, including stealth scans, with the sender named | Linux, root |
| Network sweep detected | One device asked for 25+ addresses in 10s (nmap host discovery, arp-scan) | Linux, root |

**Lure (`--lure`, opt-in):** by default your computer stays invisible. With the
Windows firewall on, a casual `nmap` decides it's offline and never scans it.
`--lure` adds a fake web login on port 80, which makes this computer show up so
scanners walk into the decoys. Use it on sweep, monitor or honeypot. It turns the
honeypot on, and you're invisible again as soon as Noxis stops. A single visit
to the lure is only medium, because smart TVs and printers sometimes check port
80. A real scan also touches the other decoys and alerts high.

Hits from your trusted devices are downgraded to medium. On Windows, allow
Python through the firewall, including on "Public" networks, or other devices
can't reach the decoys.

**Your own scans trip your own honeypot, on purpose.** If you run `noxis scan`
from your laptop while another machine runs the honeypot, that machine will
report it. The
alert names your laptop, so you'll recognise it. Noxis doesn't skip its own
scans, because then an attacker could scan you with Noxis, or pretend to be
your laptop, and go unnoticed. If a scan you run on a schedule gets noisy,
[mute it](#muting-one-alert) for that device and time.

## Data and privacy

Everything stays on your machine, in `~/.noxis` (`%USERPROFILE%\.noxis` on
Windows): trusted devices, the last scan, reports, alert settings
(`alerts.json`), what the monitor remembers (`monitor_state.json`), `alerts.log`,
`honeypot.log` and `errors.log`. Set `NOXIS_HOME` to use another folder.

Under `sudo` (needed on Linux for stealth-scan and network-sweep detection),
Noxis uses your own `~/.noxis`, not root's, and leaves the files owned by you. So
`sudo noxis monitor` and a plain `noxis trust` share the same trusted devices.

Noxis used to be called Warden. On its first run it copies an existing
`~/.warden` folder to `~/.noxis`, so trusted devices and logs carry over; the
old folder is left as a backup and can be deleted afterwards. `WARDEN_HOME`
still works if `NOXIS_HOME` isn't set.

Noxis connects to the internet only for the connection-integrity checks (a few
well-known sites), `update-oui` (the IEEE registry), and push notifications if
you set them up (only to the ntfy server you chose). Use `--no-checks` to skip
the first.

## Limits

- **Guest Wi-Fi often isolates clients from each other** (hotels, Airbnbs).
  Other devices may then be invisible. Noxis warns you when it can only see
  the router.
- **A camera on a different network, on cellular, or recording only to an SD
  card won't show up in any scan.** Do the physical check in the sweep report.
- **Sleeping phones and battery devices** can be missed in one scan. `sweep` and
  `monitor` help with this.
- **Some checks need Linux as root:** naming who sent a stealth scan, and
  detecting network sweeps. Any Linux machine works (a Pi, a homelab server, an
  old PC).
- **Wi-Fi parsing on Windows reads English `netsh` output.**
- **A perfect clone of a quiet device won't stand out.** Fingerprints catch a
  copied MAC only when the impostor behaves differently.
- **Noxis refuses to scan public IP ranges.**

## Development

```powershell
python -m unittest discover -s tests -t .
```

The layout is one module per job: `scanner` runs discovery, `fingerprint`
classifies devices, `services` names what each device hosts, `risk` turns that
into findings, and `wifi`, `mitm`, `upnp` and `honeypot` are the other
detectors. `report` handles terminal and HTML output, `store` keeps the
trusted lists, `alerts` decides what's worth an alert (presets, mutes,
repeats), and `push` sends alerts to ntfy.

### Roadmap

- [x] Router port-forward check (UPnP IGD mappings)
- [x] Faster network-settings lookup on Windows (Windows API instead of PowerShell: ~0.3 s instead of 7-12 s)
- [x] Services inventory: what each device hosts, risky services (open proxies, rogue DNS,
      fake login pages, interception tools), service trust and nicknames, change detection, `--deep`
- [ ] Always-on monitoring, on any machine that stays on (Linux recommended: a Pi, homelab server, old PC):
  - [x] Monitor survives restarts and errors, shares trusted devices with `sudo` runs, and picks
        up `trust` changes while running
  - [x] Alert presets per network (`home`, `travel`, your own), mutes, no repeated alerts
  - [ ] Runs as a background service: starts on boot, restarts if it crashes, survives closing SSH
  - [x] Push notifications through ntfy (public or self-hosted), with start/stop messages and a
        scheduled "still watching" summary
  - [ ] Root-only detection tested on real hardware: naming stealth scanners, network sweeps,
        rogue DHCP servers
  - [ ] Linux code paths tested live: network settings (`ip`), nearby Wi-Fi (`nmcli`), DNS
        (`resolv.conf`)
- [ ] Wi-Fi deauth detection (ESP32 sensor)
- [ ] DNS-based spyware and beaconing detection (an always-on box as the network's DNS)
- [ ] Tailscale-aware interface handling

## Contributing

Bug reports, feature ideas and feedback are very welcome in Issues. Noxis
doesn't accept code contributions, so pull requests won't be merged. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (C) 2026 Swadheen Mishra

Noxis is free software, licensed under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only). You can use,
study, modify and share it. If you distribute a modified version, or let other
people use one over a network, you must publish its source under the same
license.

Noxis comes with no warranty. It's a best-effort tool and can miss things.
