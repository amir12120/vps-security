# vps-security 🛡️

**English | [فارسی](README.fa.md)**

**Server security hardening for Ubuntu/Debian VPS — one beautiful interactive CLI.**

`vpssec` is a full TUI (arrow keys + emoji menu) that walks you through the essential first steps of securing a fresh server:

1. **System update** — runs `apt update && apt upgrade -y`
2. **SSH port change** — moves SSH off port 22 to a port you choose (with automatic rollback if sshd fails to come back)
3. **Firewall (ufw)** — installs ufw, opens **only** the ports you approve and enables it. You type the whole list in **one comma-separated answer** (`444,2086,2098,2689`) — every port is opened. If you specify **no ports at all**, the firewall is left **disabled** and the server stays open on every port
4. **Rogue-port monitor** — every 30 minutes scans live connections and **reports** any port outside your allow-list that is actively transferring data — with the offending IP, its country and the port. It is blocked only after *you* approve it
5. **Bot & Scanner Shield** — per-IP connection rate limits, TCP-flag scan drops (NULL / SYN+FIN / SYN+RST / ALL), and SYN-flood **detection**: a flooding IP is queued for your decision instead of being banned behind your back
6. **Approval workflow** — pending alerts appear at every SSH login, in the menu title and in the dashboard; `sudo vpssec alerts` asks you one by one: *“IP 203.0.113.5 (Netherlands) is hitting port 22 — ban it?”*. Approve → banned for **24 hours**; release it again whenever you like, so a wrong call is always recoverable
7. **Maintenance** — every 2 days clears the RAM cache (`drop_caches`), removes rotated logs, truncates active system logs, and vacuums the systemd journal (size **and** age capped). Optional swap clear is **off by default**; toggle it from the Maintenance menu or `MAINT_CLEAR_SWAP=1` in `/etc/vps-security/maintain.conf`. vps-security's own logs and any directory under `/var/log` are never touched, and you can exclude extra files via the menu or `MAINT_EXCLUDE`
8. **GeoIP country filter** — allow **any number of countries** you choose (e.g. only Iran and Germany) and block every other country from reaching the server

---

## Quick start (one line)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/amir12120/vps-security/main/install.sh)
```

The installer clones this repo to `/opt/vps-security`, installs the `vpssec` command, and starts the guided setup. **When the steps finish, the `vpssec` menu opens by itself** — the same menu you get any time later with `sudo vpssec`.

## Interactive TUI

```bash
sudo vpssec
```

```
  vps-security v1.5.0 — server hardening toolkit

  Main Menu
  ─────────────────────────────────────────────
  ❯ 🚀 Guided install (update · SSH port · firewall · monitor)
    📊 Dashboard — system security status
    🔌 Ports — add / remove allowed ports
    🔑 Change SSH port
    🔍 Scan for rogue ports now
    🚨 Pending alerts (2) — review & approve bans
    ⛔ View blocked ports
    🔓 Unblock a port
    📜 Monitor logs
    ⬆️  Update vps-security
    🧹 Maintenance — RAM cache & log cleanup
    🛡️  Bot & Scanner Shield
    🌍 GeoIP country filter
    🏁 The best Iranian mirror & DNS
    🗑️  Uninstall vps-security
    🚪 Exit
```

Navigate with **↑/↓** (or `j`/`k`), select with **Enter**, go back with **q**. Over a plain pipe (CI, scripts) it automatically falls back to a numbered menu — everything is also available as direct commands:

| Command | Description |
|---|---|
| `sudo vpssec install` | Full guided setup |
| `sudo vpssec status` | Dashboard: firewall, SSH, monitor, counts |
| `sudo vpssec ports` | Add / remove / list allowed ports |
| `sudo vpssec port` | Change the SSH port |
| `sudo vpssec scan` | Run a rogue-port scan right now (reports; then offers to review) |
| `sudo vpssec alerts` | **Review pending alerts:** y = ban (24 h), n = dismiss, s = skip, a = approve all |
| `sudo vpssec alerts list` | Print the queue without deciding |
| `sudo vpssec alerts approve <n>` / `dismiss <n>` | Act on one alert from a script |
| `sudo vpssec blocked` | View blocked ports + time until auto-release |
| `sudo vpssec unblock [port]` | Release a blocked port immediately |
| `sudo vpssec update` | Update vps-security from GitHub |
| `sudo vpssec maint run` | Run the RAM-cache & log cleanup right now |
| `sudo vpssec maint status` | Maintenance timer state + recent runs |
| `sudo vpssec maint` | Maintenance menu: run now, toggle swap clear, journal caps, skip list |
| `sudo vpssec shield status` | Bot & Scanner Shield state + banned IPs |
| `sudo vpssec geo list` | GeoIP filter configuration |
| `sudo vpssec mirror` | **The best Iranian mirror & DNS:** times every Iranian GitHub mirror and public DNS from this server, installs the fastest mirror system-wide and switches DNS — criterion: GitHub access speed |
| `sudo vpssec logs [n]` | Show monitor log |
| `sudo vpssec uninstall` | **Full cleanup:** removes everything, restores SSH to port 22, resets & disables ufw (keeping SSH reachable) |

## Detect → notify → approve (nothing is banned behind your back)

A busy service, a monitoring agent, a backup box or a tunnel peer look **exactly** like an attack from the outside, and a wrong automatic ban is very hard to notice on a live server. So vps-security stopped guessing: it **detects, tells you, and waits**.

**1. Detect.** Every 30 minutes (and on demand with `vpssec scan`) the monitor looks for ports carrying traffic outside your allow-list, and the shield looks for IPs opening floods of connections. Both record an *alert* — never a firewall rule.

**2. Notify.** Three places, so it cannot be missed:

- **at every SSH login** — `/etc/update-motd.d/99-vps-security-alerts` shows how many events wait and lists the top three
- **in the menu title** — `🚨 Pending alerts (2) — review & approve bans`
- **in `vpssec status`** — `Pending alerts : 2 suspicious event(s) — nothing blocked yet`

**3. Approve.** `sudo vpssec alerts` walks the queue one event at a time and asks exactly one question per event:

```
  🚨 IP 203.0.113.5 (Netherlands) hitting port 22 — 45 new connections to port 22 in 30s (2m ago)
     Ban IP 203.0.113.5 for 24h?  [y = yes · n = no, dismiss · s = skip · a = approve all · q = stop]

  🚨 Port 3389 — rogue tcp service carrying traffic, not in your allow-list (just now)
     Block port 3389 for 24h?  [y = yes · n = no, dismiss · s = skip · a = approve all · q = stop]
```

- **y** → the ban/block is applied to ufw for **24 hours**
- **n** → dismissed, the firewall is not touched (and the entry is remembered as reviewed)
- **s** → keep it queued for later, **a** → approve everything, **q** → stop

The country shown is resolved offline from the GeoIP country lists vps-security already downloaded (or `geoiplookup`, if you have it installed) — no request ever leaves the server for it.

**4. Expire or release.** Nothing is permanent: the monitor and shield timers remove expired bans automatically, and you can release one immediately — `sudo vpssec unblock <port>`, `sudo vpssec shield unban <ip>`, or the menu items **🔓 Unblock a port** / **🛡️ Shield → Unban an IP**.

**What is never even queued:** allow-listed ports, declared tunnel ports, the SSH port, the guard API port, ports you already opened in ufw, loopback-only services, private/CGNAT peers, and IPs on your GeoIP *never block* list. Skips are logged to `/var/lib/vps-security/alerts.log`.

**Want the old fully-automatic behaviour?** It is still there, one setting away:

```bash
MONITOR_MODE=auto   # /etc/vps-security/monitor.conf — blocks rogue ports immediately
SHIELD_MODE=auto    # /etc/vps-security/botshield.conf — bans SYN-flood IPs immediately
```

## The best Iranian mirror & DNS

On Iranian servers, GitHub is often slow or unreachable. The **🏁 The best Iranian mirror & DNS** menu item (or `vpssec mirror`) fixes this by measurement, not guessing:

1. **Mirrors** — probes every Iranian GitHub mirror (`gitclone.ir`, `github.iranserver.com`, `gitdl.theazizi.ir`) plus the direct route, timing real HTTPS fetches of the git smart-HTTP endpoint. The winner is installed **system-wide** via `git config --system url.<mirror>.insteadOf https://github.com/`, so every `git clone/pull/fetch` — including `vpssec update` — is redirected automatically.
2. **DNS** — queries each Iranian public DNS (Shecan, 403.online, Radar, Begzar, Electro, Pishgaman, Shelter) for `github.com` and switches the server to the fastest answerer (systemd-resolved drop-in, or `/etc/resolv.conf` with backup otherwise). A backup makes the change fully reversible.

`sudo vpssec mirror reset` undoes both changes (removes insteadOf, restores the original DNS). `sudo vpssec mirror status` shows what is applied.

## How the rogue-port monitor works

- A systemd timer runs the scanner **every 30 minutes** (`OnBootSec=2min`, then `OnUnitActiveSec=30min`).
- The scanner reads live sockets from `ss -tunap` and keeps only **services bound on a public address**: TCP ports with a `LISTEN` socket that is actually serving connections, and UDP ports bound outside the ephemeral range. Outbound sockets — the local ports your tunnels, panel API calls and updates use — are never candidates.
- Any such port **not** in `/etc/vps-security/allowed-ports.list`, not declared as a tunnel port, and not already opened in ufw is recorded as a **pending alert** (`/var/lib/vps-security/pending-alerts.list`) and reported to you. **Nothing is blocked yet.**
- Approving the alert is what runs `ufw deny <port>/{tcp,udp}` — for **86400 seconds (24 h)**, configurable via `BLOCK_SECONDS` in `/etc/vps-security/monitor.conf`.
- After the window expires, the next scan removes the rule and logs `UNBLOCK`.
- View currently blocked ports (with a live countdown) via the **⛔ View blocked ports** menu or `vpssec blocked`; release a port early via **🔓 Unblock a port** or `vpssec unblock <port>`.
- The SSH port itself and the monitor's own ports are **never** blocked — even if they are not in the allow-list.
- All actions are logged to `/var/lib/vps-security/port-blocks.log` and `/var/lib/vps-security/monitor.log`.

> **Note:** the scanner sees ports with live connections. A port that only *listens* without transferring data is not flagged — this keeps the tool safe around services that legitimately listen (docker proxies, panel sockets, …).

## Tunnels, reverse proxies and VPN servers

These servers usually carry a tunnel, so nothing here may fight it. vps-security is built around that:

- **Outbound connections are never touched.** A tunnel that dials a foreign server, a panel API call, a `git fetch` — all use kernel-assigned ephemeral ports, and the monitor ignores them completely. (Older builds blocked those source ports, which throttled the tunnel and filled ufw with junk rules.)
- **Declare your tunnel ports** — `sudo vpssec tunnels add 8443,51820` or **🔌 Ports → 🚇 Tunnel ports**. A declared port is opened in the firewall, **never** blocked by the monitor, and **never** rate-limited by the shield.
- **The shield never throttles a tunnel.** `ufw limit` drops a source after ~6 new connections in 30 s, and a busy tunnel peer looks exactly like that — tunnel ports are excluded from `ufw limit` and from the auto-ban scan.
- **Peers are never banned blindly.** The shield refuses to ban loopback, RFC1918/CGNAT/link-local addresses and anything on your GeoIP *never block* list (`vpssec geo bypass <ip>`) — add the tunnel peer's IP there.
- **Loopback services and the DNS resolver** are never flagged; the GeoIP filter never touches loopback traffic.
- **The country filter only drops NEW inbound connections** (`--ctstate NEW`, `! -i lo`). Replies to connections *your server* opened keep flowing, so enabling GeoIP cannot kill an outbound tunnel — no matter which country the foreign server sits in.
- **Reinstalling keeps your rules.** Before it resets ufw, the installer reads your existing `ALLOW` rules and re-applies them, so a tunnel or panel port you opened earlier survives setup.
- **It tells you what it sees.** Install prints the ports listening right now and asks you to declare the tunnel ones; `vpssec status` lists the declared tunnel ports.

```bash
sudo vpssec tunnels add 8443      # declare (also opens it in ufw)
sudo vpssec tunnels list          # show what is protected
sudo vpssec tunnels remove 8443   # stop protecting it
```

## Maintenance details

The maintenance timer runs every 2 days (with up to 15 minutes of random startup jitter so servers don't all clean at once).

| Setting (`/etc/vps-security/maintain.conf`) | Default | Purpose |
|---|---|---|
| `MAINT_CLEAR_SWAP` | `0` | `swapoff/swapon` cycle — risky on busy VPS (OOM killer), keep off |
| `MAINT_JOURNAL_MAX` | `200M` | journald size cap (`--vacuum-size`) |
| `MAINT_JOURNAL_MAX_TIME` | `7d` | journald age cap (`--vacuum-time`) |
| `MAINT_EXCLUDE` | — | extra top-level `/var/log` files to never touch, comma-separated |

Everything is editable from the 🧹 **Maintenance** menu too (`vpssec maint`).

## Bot & Scanner Shield

Enable it from the **🛡️ Bot & Scanner Shield** menu (or `vpssec shield enable`):

- **Rate limiting** — ufw `limit` rules on SSH and every protected port: more than **6 new connections per 30 s** from one IP are dropped (this kills port scanners and brute-force bots). **Tunnel ports are excluded** — declare them with `vpssec tunnels add`.
- **Ban safety** — IPs are never banned for loopback, private/CGNAT/link-local addresses, or peers on your GeoIP *never block* list; skips are logged.
- **TCP-flag drops** — NULL scans, SYN+FIN, SYN+RST, and ALL-flags packets are dropped in ufw's `before.rules` (survives reboots and ufw reloads)
- **Detection instead of auto-ban** — an IP flooding a protected port with half-open connections (40+ SYN-RECV) is **reported as a pending alert** (`sudo vpssec alerts`), not banned. Approving it applies `ufw deny from <ip>` for **24 hours** (`BAN_SECONDS` in `/etc/vps-security/botshield.conf`); bans expire automatically (10-minute maintenance timer) and can be released immediately. Your **SSH port is always included** in the scan, so SSH brute-force floods are caught too — while declared **tunnel ports are never rate-limited and never reported** (one busy tunnel peer would otherwise look like a flood)
- Manage banned IPs from the same menu: view the list with remaining time, or unban any IP instantly

## GeoIP country filter

From the **🌍 GeoIP country filter** menu (or `vpssec geo ...`):

1. **➕ Add allowed countries** — enter any number of countries, however you happen to spell them — the list is unlimited. **120+ countries** are built in, and matching is forgiving:
   - 2-letter codes: `IR,DE,TR,US`
   - **full names**: `Iran,Germany,Netherlands,Turkey`
   - **Persian names**: `ایران,آلمان,هلند,ترکیه`
   - ISO alpha-3, any case: `USA,IRN,deu`
   - **aliases**: `holland`, `deutschland`, `england`, `dubai`, `america`, `korea`
   - short forms and obvious typos: `netherland`, `nederlands`, `germny`, `qater` all resolve
   - Unknown or **ambiguous** entries change nothing and print a hint: `'Turk' is not a valid country code or name … Did you mean: TR (turkey), TM (turkmenistan) ?`
   - Not sure of a code? **📖 Country codes & names** in the menu (or `vpssec geo names`) prints the whole code/name/alias table.
2. **✅ Enable filtering** — downloads each country's IPv4 CIDR list (IPFire location database, updated daily), loads them into an **ipset**, and wires ufw so that *only* those countries can reach the server — everyone else is dropped
3. **🛟 Bypass** — add your own IP so it is never geo-blocked, even from a blocked country (the menu shows your current public IP)
4. **♻️ Refresh** — country lists refresh automatically every week; refresh manually any time
5. **⛔ Disable** — removes all geo rules instantly; everyone can connect again

Direct commands: `vpssec geo add IR,DE` (codes, full names, or Persian names) · `vpssec geo remove TR` · `vpssec geo names` (lookup table) · `vpssec geo list` · `vpssec geo enable|disable` · `vpssec geo bypass <ip>` · `vpssec geo refresh`

> ⚠️ Enable GeoIP filtering **after** confirming your SSH connectivity, and add your own IP as a bypass if you connect from a country you did not whitelist.

> 🛡️ **Built-in safety — you can never lock the whole world out by accident:**
> - If **no countries are configured**, enabling the filter is refused and the server stays reachable from **everywhere**.
> - If every country-list **download fails**, the blocking rules are never installed.
> - **Removing the last allowed country** while filtering is active automatically disables the filter and re-opens the server to all countries.
> - **At boot**, an unsafe config (no countries / empty lists / no bypass) never re-applies the world-DROP rule.

## Files and paths

| Path | Purpose |
|---|---|
| `/usr/local/bin/vpssec` | CLI entry point |
| `/usr/local/share/vps-security/` | Installed libraries (monitor, guard, shield, geo, maintenance, mirror) |
| `/etc/vps-security/allowed-ports.list` | Your approved ports |
| `/etc/vps-security/monitor.conf` | Monitor config (self ports, `MONITOR_MODE`, `BLOCK_SECONDS`) |
| `/etc/vps-security/botshield.conf` | Bot & Scanner Shield config (`SHIELD_MODE`, `BAN_SECONDS`) |
| `/etc/vps-security/geo.conf` | GeoIP config (countries, bypass IPs) |
| `/etc/vps-security/mirror.conf` | Applied mirror & DNS choice |
| `/var/lib/vps-security/pending-alerts.list` | Suspicious events **awaiting your approval** |
| `/var/lib/vps-security/blocked-ports.list` | Currently blocked ports |
| `/var/lib/vps-security/shield-bans.list` | Banned IPs |
| `/etc/update-motd.d/99-vps-security-alerts` | Login notice for pending alerts (removed by uninstall) |
| `/var/lib/vps-security/*.log` | Monitor, ban, geo and maintenance logs |
| `/etc/systemd/system/vps-security-*` | systemd units (monitor, shield, geo, maintenance) |
| `/etc/systemd/system/vps-security-guard.service` | Local status API |

## Guard API (local status endpoint)

The optional guard service serves monitor state on `127.0.0.1:18080`:

```bash
curl http://127.0.0.1:18080/health   # {"status":"ok"}
curl http://127.0.0.1:18080/status   # allowed, blocked, pending_alerts, recent events
```

`pending_alerts` is the number of events detected but **not yet approved** — it can be non-zero while nothing is firewalled.

It stays local-only by default — do not expose it publicly without an authenticated reverse proxy.

## Safety notes

- The SSH-port change **backs up** `sshd_config`, validates with `sshd -t`, and **rolls back automatically** if sshd does not come up on the new port.
- ufw is enabled **after** your approved ports (including SSH) are allowed, so you can never lock yourself out.
- **Nothing is banned without your approval.** The monitor and shield only record alerts; a ban or block is applied after you press **y** (`vpssec alerts`). Allow-listed ports, tunnel ports, the SSH port, loopback/private peers and GeoIP-bypassed IPs are never even queued.
- **Every ban is temporary and releasable.** Approved bans last 24 hours, expire on their own via the timers, and can be released early with `vpssec unblock <port>` or `vpssec shield unban <ip>` — mistakes stay recoverable.
- `vpssec uninstall` performs a **full factory reset**: stops and removes all services, deletes every vps-security config/state file, restores the SSH port to **22**, and runs `ufw reset` → `ufw allow 22` → `ufw disable`, so the server ends up exactly as it started — open, with SSH on port 22.

## Troubleshooting

- **The `vpssec` menu does not appear.** Run `sudo vpssec --version` and `sudo vpssec help`: if the CLI prints an error like *libraries not found*, the install is incomplete — re-run the one-line installer.
- **Nothing happens over SSH?** The CLI needs a terminal. Over a plain pipe (CI, `cron`, some web consoles) it automatically switches to a numbered menu instead of the arrow-key TUI.
- **Automation / unattended installs.** Export `VPSSEC_NO_MENU=1` to run `vpssec install` without opening the menu when it finishes.
- **Just want the menu back after a command?** Any command exits back to your shell; run `sudo vpssec` to reopen the menu.
- **Too many alerts?** Review them with `sudo vpssec alerts` (**n** dismisses, **a** approves all) or silence a known service for good by adding its port: `sudo vpssec ports` (allowed) or `sudo vpssec tunnels add <port>`. To go back to fully automatic banning, set `MONITOR_MODE=auto` / `SHIELD_MODE=auto`.
- **Alerts but no login notice?** The notice lives in `/etc/update-motd.d/99-vps-security-alerts` and only prints when the queue is non-empty; set `VPSSEC_STATE_DIR` if you moved the state directory.

## Requirements

- Ubuntu 20.04+ / Debian 11+ (uses `ss`, `ufw`, `systemd`, `python3` for the guard API, `ipset` for the GeoIP filter — auto-installed when needed)
- root access

## Tests

Nothing here touches the machine it runs on: `ufw`, `ss`, `systemctl`, `apt-get`, `ipset` and `curl` are `PATH`-stubbed and every path is redirected into a temp sandbox.

```bash
bash test/smoke.sh              # 266 checks: full install, alert detection + approval, ban expiry, shield, GeoIP, maintenance, mirror/DNS, symlinked CLI, TUI frames, uninstall
                                # (a Linux host adds the pty menu checks, the interactive y/n approval and the live guard API checks)
bash test/simulate-two-host.sh  #  76 checks: two simulated servers (Iran + foreign) with a 3x-ui panel and a backpack tunnel
```

The two-host simulation models the real deployment — a foreign server running the 3x-ui/Sanayi panel (`2087` API, `2096` subscriptions) and a backpack **tunnel server** on `8443`, plus an Iran server with the tunnel **client** on `443` dialling out to it and reaching the panel over `127.0.0.1:2087`. It installs vps-security on **both** hosts, then proves the security stack never breaks the tunnel: tunnel and panel ports are opened and never blocked, reported or rate-limited, outbound tunnel sockets and loopback forwards are ignored, **real rogue ports are still detected and blocked once approved**, GeoIP drops NEW connections only, a re-install adopts the tunnel rules instead of cutting them, and uninstalling on Iran leaves the foreign server untouched.

Both suites run automatically in **GitHub Actions** on every push (`.github/workflows/deploy-smoke-test.yml`).

## Roadmap

- [ ] Telegram/email delivery of pending alerts (the SSH login notice covers the basics today)
- [ ] Remote dashboard reading the guard API
- [ ] Fail2ban integration
- [ ] Whitelist by process name, not only port

## License

MIT © amir12120
