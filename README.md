# vps-security 🛡️

**Server security hardening for Ubuntu/Debian VPS — one interactive CLI.**

`vpssec` walks you through the essential first steps of securing a fresh server:

1. **System update** — runs `apt update && apt upgrade -y`
2. **SSH port change** — moves SSH off port 22 to a port you choose (with automatic rollback if sshd fails to come back)
3. **Firewall (ufw)** — installs ufw, opens **only** the ports you approve, and enables it
4. **Rogue-port monitor** — every 30 minutes scans live connections; any port **not** in your allow-list that is actively transferring data gets **blocked via ufw for 1 hour**, then automatically released

---

## Quick start (one line)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/amir12120/vps-security/main/install.sh)
```

The installer clones this repo to `/opt/vps-security`, installs the `vpssec` command, and starts the guided setup.

## Interactive CLI

```bash
sudo vpssec
```

```
==============================================
   vps-security 1.0.0
==============================================
 1) Guided install (update/SSH/firewall/monitor)
 2) Status
 3) Manage allowed ports
 4) Change SSH port
 5) Monitor status and events
 6) Unblock a port now
 7) Logs
 8) Uninstall
 0) Exit
==============================================
```

Direct commands:

| Command | Description |
|---|---|
| `sudo vpssec install` | Full guided setup (the 4 steps above) |
| `sudo vpssec status` | Firewall, SSH and monitor status |
| `sudo vpssec ports` | View / add / remove allowed ports |
| `sudo vpssec port` | Change the SSH port |
| `sudo vpssec monitor` | Monitor status + recent block events |
| `sudo vpssec unblock <port>` | Release a blocked port immediately |
| `sudo vpssec logs [n]` | Show monitor log |
| `sudo vpssec uninstall` | Remove vps-security (ufw rules are kept) |

## How the rogue-port monitor works

- A systemd timer runs the scanner **every 30 minutes** (`OnBootSec=2min`, then `OnUnitActiveSec=30min`).
- The scanner reads live connections from `ss -tunap` and collects the **local ports with active traffic** (established TCP, connected UDP).
- Any such port **not** in `/etc/vps-security/allowed-ports.list` is added to ufw as `deny <port>/{tcp,udp}` for **3600 seconds**.
- After the hour expires, the next scan removes the rule and logs `UNBLOCK`.
- The SSH port itself and the monitor's own ports are **never** blocked — even if they are not in the allow-list.
- All actions are logged to `/var/lib/vps-security/port-blocks.log` and `/var/lib/vps-security/monitor.log`.

> **Note:** the scanner sees ports with live connections. A port that only *listens* without transferring data is not flagged — this keeps the tool safe around services that legitimately listen (docker proxies, panel sockets, …).

## Files and paths

| Path | Purpose |
|---|---|
| `/usr/local/bin/vpssec` | CLI entry point |
| `/usr/local/share/vps-security/` | Installed libraries (monitor, guard) |
| `/etc/vps-security/allowed-ports.list` | Your approved ports |
| `/etc/vps-security/monitor.conf` | Monitor config (self ports) |
| `/var/lib/vps-security/blocked-ports.list` | Currently blocked ports |
| `/var/lib/vps-security/*.log` | Monitor and block logs |
| `/etc/systemd/system/vps-security-monitor.{service,timer}` | Scanner units |
| `/etc/systemd/system/vps-security-guard.service` | Local status API |

## Guard API (local status endpoint)

The optional guard service serves monitor state on `127.0.0.1:18080`:

```bash
curl http://127.0.0.1:18080/health   # {"status":"ok"}
curl http://127.0.0.1:18080/status   # allowed, blocked, recent events
```

It stays local-only by default — do not expose it publicly without an authenticated reverse proxy. It is ready as a data source for a future remote dashboard.

## Safety notes

- The SSH-port change **backs up** `sshd_config`, validates with `sshd -t`, and **rolls back automatically** if sshd does not come up on the new port.
- The old SSH port stays open until you confirm the new one works, and is only closed after you approve.
- ufw is enabled **after** your approved ports (including SSH) are allowed, so you can never lock yourself out.
- `vpssec uninstall` removes the tool but **never** touches your existing ufw rules or SSH config.

## Requirements

- Ubuntu 20.04+ / Debian 11+ (uses `ss`, `ufw`, `systemd`, `python3` for the guard API)
- root access

## Roadmap

- [ ] Telegram/email notifications when a port is blocked
- [ ] Remote dashboard reading the guard API
- [ ] Fail2ban integration
- [ ] Whitelist by process name, not only port

## License

MIT © amir12120
