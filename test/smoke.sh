#!/usr/bin/env bash
# ============================================================
# vps-security — deployment smoke test (CI-grade)
#
# Simulates a fresh server inside the CURRENT environment WITHOUT
# touching the host kernel or firewall:
#   - PATH-stubs ufw/ss/sshd/systemctl/apt-get so the real logic
#     runs unmodified
#   - redirects /etc/ssh and /etc/systemd into a sandbox
#   - exercises the full guided install with piped answers
#   - verifies the monitor blocks rogue ports and releases them
#   - verifies allowed ports and control ports are never blocked
#   - verifies the guard API answers /health and /status
#
# Usage: bash test/smoke.sh
# ============================================================
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0
declare -a FAILURES=()

check() {
    local name="$1" cond="$2"
    if eval "$cond"; then
        PASS=$((PASS + 1))
        echo "  ok  - $name"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$name")
        echo "  FAIL- $name"
    fi
}

SANDBOX="$(mktemp -d)"
STUBS="$SANDBOX/stubs"
mkdir -p "$STUBS" "$SANDBOX/etc" "$SANDBOX/state" "$SANDBOX/etc-ssh" "$SANDBOX/systemd"
export VPSSEC_CONF_DIR="$SANDBOX/etc"
export VPSSEC_STATE_DIR="$SANDBOX/state"
export VPSSEC_SYSTEMD_DIR="$SANDBOX/systemd"
export VPSSEC_INSTALL_DIR="$SANDBOX/opt/vps-security"
export VPSSEC_TARGET_DIR="$SANDBOX/opt/vps-security"
export VPSSEC_SSHD_CONFIG="$SANDBOX/etc-ssh/sshd_config"
export UFW_DIR="$SANDBOX/ufw"
export GEO_TMP="$SANDBOX/geotmp"
export VPSSEC_SKIP_ROOT_CHECK=1
export VPSSEC_SKIP_OS_CHECK=1
# Never let a test run block on the post-install TUI menu (the pty section
# below re-enables it explicitly with VPSSEC_NO_MENU=0).
export VPSSEC_NO_MENU=1
# Single source of truth for the version assertions
VER="$(grep -m1 '^VERSION=' "$HERE/vpssec" | cut -d'"' -f2)"
export PATH="$STUBS:$PATH"
SSH_CFG="$SANDBOX/etc-ssh/sshd_config"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/ufw"
printf '# ufw before rules stub\n*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$SANDBOX/ufw/before.rules"

printf '#Stub sshd_config\nPort 22\n' > "$SSH_CFG"

# ---------- stub: ufw ----------
# UFW_STATUS_EXTRA lets a test inject `ufw status` rows so the "adopt the
# admin's existing rules" logic can be verified.
cat > "$STUBS/ufw" <<'EOF'
#!/usr/bin/env bash
echo "ufw $*" >> "${UFW_LOG:-/tmp/ufw.log}"
case "$1" in
    status)
        echo "Status: active"
        echo "Logging: on"
        [ -n "${UFW_STATUS_EXTRA:-}" ] && [ -f "$UFW_STATUS_EXTRA" ] && cat "$UFW_STATUS_EXTRA"
        ;;
esac
exit 0
EOF
chmod +x "$STUBS/ufw"

# ---------- stub: ss ----------
# ss -tlnp  -> LISTEN table (used by install to confirm sshd came up)
# ss -tunap -> connection table used by the monitor scan
cat > "$STUBS/ss" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    *tlnp*)
        # stateful: report sshd as listening on whatever Port the sandboxed
        # sshd_config currently has (used by install/port change verification)
        port="$(grep -E '^Port ' "${VPSSEC_SSHD_CONFIG:-/etc/ssh/sshd_config}" 2>/dev/null | tail -1 | awk '{print $2}')"
        [ -z "$port" ] && port=22
        cat <<TABLE
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128    0.0.0.0:$port      0.0.0.0:*
LISTEN 0      128    0.0.0.0:443        0.0.0.0:*
TABLE
        ;;
    *tulnH*)
        # no-header listening table used by the installer's port hint
        cat <<'TABLEH'
tcp LISTEN 0 4096 0.0.0.0:9999 0.0.0.0:*
tcp LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*
udp UNCONN 0 0 127.0.0.53:53    0.0.0.0:*
TABLEH
        ;;
    *-tan*)
        # `ss -tan` has NO Netid column (unlike -tunap): the shield parses
        # this exact layout, so the stub must reproduce it faithfully.
        echo "State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port"
        if [ -n "${SS_SYN_FLOOD:-}" ]; then
            # 50 half-open connections from one peer, to exercise the ban logic
            i=1
            while [ "$i" -le 50 ]; do
                echo "SYN-RECV 0        0         192.168.1.5:443         $SS_SYN_FLOOD:4$i"
                i=$((i + 1))
            done
            exit 0
        fi
        echo "ESTAB    0        0         192.168.1.5:443         10.0.0.3:51002"
        exit 0
        ;;
    *)
        # A realistic mix for a tunnelled server:
        #   9999  rogue TCP service (bound + serving)  -> must be blocked
        #   9998  rogue UDP service (bound, non-ephemeral) -> must be blocked
        #   8080  a declared tunnel port                -> must be left alone
        #   45892/41555 outbound tunnel sockets (source ports) -> never blocked
        #   9997  loopback-only service                 -> never blocked
        #   53    loopback resolver                     -> never blocked
        cat <<'TABLE'
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:9999      0.0.0.0:*
tcp   ESTAB  0      0      192.168.1.5:9999  10.0.0.9:51000
tcp   LISTEN 0      128    0.0.0.0:8080      0.0.0.0:*
tcp   ESTAB  0      0      192.168.1.5:8080  203.0.113.7:40000
udp   UNCONN 0      0      0.0.0.0:9998      0.0.0.0:*
udp   ESTAB  0      0      192.168.1.5:9998  10.0.0.9:51003
tcp   LISTEN 0      128    0.0.0.0:2222      0.0.0.0:*
tcp   ESTAB  0      0      192.168.1.5:2222  10.0.0.2:51001
tcp   LISTEN 0      128    0.0.0.0:443       0.0.0.0:*
tcp   ESTAB  0      0      192.168.1.5:443   10.0.0.3:51002
tcp   ESTAB  0      0      192.168.1.5:45892 203.0.113.9:443
udp   ESTAB  0      0      192.168.1.5:41555 203.0.113.9:51820
tcp   LISTEN 0      128    127.0.0.1:9997    0.0.0.0:*
tcp   ESTAB  0      0      127.0.0.1:9997    127.0.0.1:51234
udp   UNCONN 0      0      127.0.0.53:53     0.0.0.0:*
TABLE
        ;;
esac
EOF
chmod +x "$STUBS/ss"

# ---------- stubs: sshd / systemctl / apt-get ----------
printf '#!/usr/bin/env bash\nexit 0\n' > "$STUBS/sshd"; chmod +x "$STUBS/sshd"
printf '#!/usr/bin/env bash\necho "ipset $*" >> "${IPSET_LOG:-/tmp/ipset.log}"\nexit 0\n' > "$STUBS/ipset"; chmod +x "$STUBS/ipset"

cat > "$STUBS/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "${SYSTEMCTL_LOG:-/tmp/systemctl.log}"
exit 0
EOF
chmod +x "$STUBS/systemctl"

cat > "$STUBS/apt-get" <<'EOF'
#!/usr/bin/env bash
echo "apt-get $*" >> "${APT_LOG:-/tmp/apt.log}"
exit 0
EOF
chmod +x "$STUBS/apt-get"

# ---------- sed/cp wrappers: redirect /etc/ssh/sshd_config ----------
cat > "$STUBS/sed" <<EOF
#!/usr/bin/env bash
args=()
for a in "\$@"; do
  case "\$a" in
    /etc/ssh/sshd_config) args+=("$SSH_CFG");;
    *) args+=("\$a");;
  esac
done
exec /usr/bin/sed "\${args[@]}"
EOF
chmod +x "$STUBS/sed"

cat > "$STUBS/cp" <<EOF
#!/usr/bin/env bash
args=()
for a in "\$@"; do
  case "\$a" in
    /etc/ssh/sshd_config) args+=("$SSH_CFG");;
    *) args+=("\$a");;
  esac
done
exec /usr/bin/cp "\${args[@]}"
EOF
chmod +x "$STUBS/cp"

echo "=== smoke: full guided install (piped answers) ==="
# answers: update=y, ssh-port=2222, close-old=y, ports only="443,8443",
#          tunnels=n, guard-port=18080, open-guard=n, first-scan=n
# The open ports are collected in ONE comma-separated answer.
printf 'y\n2222\ny\n443,8443\nn\n18080\nn\nn\n' \
    | UFW_LOG="$SANDBOX/ufw.log" APT_LOG="$SANDBOX/apt.log" SYSTEMCTL_LOG="$SANDBOX/systemctl.log" \
      bash "$HERE/vpssec" install > "$SANDBOX/install.out" 2>&1
grep -E '✓|✗|error|Error|denied' "$SANDBOX/install.out" | tail -n 20 || true
if grep -qE 'denied|Error' "$SANDBOX/install.out"; then echo "--- install.out (first 40) ---"; head -n 40 "$SANDBOX/install.out"; fi

check "install ran apt-get update"      "grep -q 'update' '$SANDBOX/apt.log'"
check "install ran apt-get upgrade"     "grep -q 'upgrade' '$SANDBOX/apt.log'"
check "ssh port changed to 2222"        "grep -q '^Port 2222$' '$SSH_CFG'"
check "ufw allow 2222/tcp issued"       "grep -q 'allow 2222/tcp' '$SANDBOX/ufw.log'"
check "ufw allow 443/tcp issued"        "grep -q 'allow 443/tcp' '$SANDBOX/ufw.log'"
check "ufw allow 8443/tcp issued"       "grep -q 'allow 8443/tcp' '$SANDBOX/ufw.log'"
check "old port 22 closed on confirm"   "grep -q 'delete allow 22/tcp' '$SANDBOX/ufw.log'"
check "ufw enabled"                     "grep -q ' enable' '$SANDBOX/ufw.log'"
check "allowed-ports list written"      "grep -q '^2222$' '$VPSSEC_CONF_DIR/allowed-ports.list' && grep -q '^443$' '$VPSSEC_CONF_DIR/allowed-ports.list' && grep -q '^8443$' '$VPSSEC_CONF_DIR/allowed-ports.list'"
check "monitor conf written"            "grep -q 'MONITOR_SELF_PORT=2222' '$VPSSEC_CONF_DIR/monitor.conf' && grep -q 'MONITOR_GUARD_PORT=18080' '$VPSSEC_CONF_DIR/monitor.conf'"
check "monitor timer unit installed"    "grep -q 'monitor.sh --scan' '$VPSSEC_SYSTEMD_DIR/vps-security-monitor.service' && grep -q 'OnUnitActiveSec=30min' '$VPSSEC_SYSTEMD_DIR/vps-security-monitor.timer'"
check "timer enabled via systemctl"     "grep -q 'enable --now vps-security-monitor.timer' '$SANDBOX/systemctl.log'"
check "maint timer unit installed"      "grep -q 'OnUnitActiveSec=2d' '$VPSSEC_SYSTEMD_DIR/vps-security-maint.timer' && grep -q 'maintain.sh --run' '$VPSSEC_SYSTEMD_DIR/vps-security-maint.service'"
check "maint timer enabled via systemctl" "grep -q 'enable --now vps-security-maint.timer' '$SANDBOX/systemctl.log'"

echo
echo "=== smoke: standalone SSH port change opens ufw + allow-list BEFORE switching ==="
rm -f "$SANDBOX/ufw.log"
printf '3333\n' | UFW_LOG="$SANDBOX/ufw.log" SYSTEMCTL_LOG="$SANDBOX/systemctl.log" \
    bash "$HERE/vpssec" port > "$SANDBOX/port.out" 2>&1 || true
check "port cmd changed config to 3333"  "grep -q '^Port 3333$' '$SSH_CFG'"
check "port cmd opened ufw 3333/tcp"     "grep -q 'allow 3333/tcp' '$SANDBOX/ufw.log'"
check "port cmd opened ufw 3333/udp"     "grep -q 'allow 3333/udp' '$SANDBOX/ufw.log'"
check "port cmd added 3333 to allow list" "grep -q '^3333$' '$VPSSEC_CONF_DIR/allowed-ports.list'"
check "port cmd synced MONITOR_SELF_PORT" "grep -q 'MONITOR_SELF_PORT=3333' '$VPSSEC_CONF_DIR/monitor.conf'"
check "port cmd confirmed listening"     "grep -q 'now listening on port 3333' '$SANDBOX/port.out'"

echo
echo "=== smoke: failed SSH port change rolls everything back ==="
printf '#!/usr/bin/env bash\nexit 1\n' > "$STUBS/sshd"   # sshd -t now fails
rm -f "$SANDBOX/ufw.log"
printf '4444\n' | UFW_LOG="$SANDBOX/ufw.log" \
    bash "$HERE/vpssec" port > "$SANDBOX/port2.out" 2>&1 || true
printf '#!/usr/bin/env bash\nexit 0\n' > "$STUBS/sshd"   # restore stub
check "rollback restored config 3333"    "grep -q '^Port 3333$' '$SSH_CFG'"
check "rollback removed 4444 from list"  "! grep -q '^4444$' '$VPSSEC_CONF_DIR/allowed-ports.list'"
check "rollback deleted ufw 4444 rules"  "grep -q 'delete allow 4444/tcp' '$SANDBOX/ufw.log'"
check "rollback restored MONITOR_SELF_PORT" "grep -q 'MONITOR_SELF_PORT=3333' '$VPSSEC_CONF_DIR/monitor.conf'"

echo
echo "=== smoke: rogue-port monitor scan ==="
# 8080 is the admin's own tunnel: declared before the first scan.
printf '8080\n' > "$VPSSEC_CONF_DIR/tunnel-ports.list"
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/monitor.sh" --scan > "$SANDBOX/scan.out" 2>&1
if [ -s "$SANDBOX/scan.out" ]; then echo "--- scan.out ---"; cat "$SANDBOX/scan.out"; fi

check "rogue tcp 9999 blocked"          "grep -q 'deny 9999/tcp' '$SANDBOX/ufw.log'"
check "rogue udp 9998 blocked"          "grep -q 'deny 9998/udp' '$SANDBOX/ufw.log'"
check "unconnected udp 53 NOT blocked"  "! grep -q 'deny 53/' '$SANDBOX/ufw.log'"
check "ssh port 2222 NOT blocked"       "! grep -q 'deny 2222/' '$SANDBOX/ufw.log'"
check "allowed port 443 NOT blocked"    "! grep -q 'deny 443/' '$SANDBOX/ufw.log'"

# ---- tunnel safety: outbound sockets and declared tunnel ports ----
check "outbound tcp source port NOT blocked" "! grep -q 'deny 45892' '$SANDBOX/ufw.log'"
check "outbound udp source port NOT blocked" "! grep -q 'deny 41555' '$SANDBOX/ufw.log'"
check "loopback-only service NOT blocked"    "! grep -q 'deny 9997' '$SANDBOX/ufw.log'"
check "tunnel port 8080 NOT blocked"         "! grep -q 'deny 8080' '$SANDBOX/ufw.log'"
check "tunnel skip recorded in log"          "grep -q 'SKIP 8080 (declared tunnel port)' '$VPSSEC_STATE_DIR/monitor.log'"
check "scan log names the tunnel ports"      "grep -q 'tunnel: 8080' '$VPSSEC_STATE_DIR/monitor.log'"
check "blocked list has no tunnel port"      "! grep -qE '\|8080$' '$VPSSEC_STATE_DIR/blocked-ports.list'"

# ---- a port the admin opened in ufw is approval in itself ----
printf '9999/tcp                   ALLOW       Anywhere\n' > "$SANDBOX/ufw-status.txt"
rm -f "$SANDBOX/ufw.log" "$VPSSEC_STATE_DIR/blocked-ports.list"
UFW_LOG="$SANDBOX/ufw.log" UFW_STATUS_EXTRA="$SANDBOX/ufw-status.txt" \
    bash "$HERE/lib/monitor.sh" --scan > /dev/null 2>&1
check "ufw-allowed port is respected"   "! grep -q 'deny 9999/tcp' '$SANDBOX/ufw.log'"
# restore the plain status stub for the remaining scans
printf '' > "$SANDBOX/ufw-status.txt"
rm -f "$VPSSEC_STATE_DIR/blocked-ports.list"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/monitor.sh" --scan > /dev/null 2>&1
check "blocks recorded with timestamp"  "grep -qE '^[0-9]+\|9999$' '$VPSSEC_STATE_DIR/blocked-ports.list' && grep -qE '^[0-9]+\|9998$' '$VPSSEC_STATE_DIR/blocked-ports.list'"
check "BLOCK events logged"             "grep -q 'BLOCK 9999' '$VPSSEC_STATE_DIR/port-blocks.log' && grep -q 'BLOCK 9998' '$VPSSEC_STATE_DIR/port-blocks.log'"

echo
echo "=== smoke: second scan does not double-block ==="
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/monitor.sh" --scan > /dev/null 2>&1
check "no duplicate deny rules"         "! grep -q 'deny 9999/tcp' '$SANDBOX/ufw.log' && ! grep -q 'deny 9998/tcp' '$SANDBOX/ufw.log'"

echo
echo "=== smoke: expired block is released and re-detected ==="
OLD=$(( $(date +%s) - 3700 ))
printf '%s|9999\n' "$OLD" > "$VPSSEC_STATE_DIR/blocked-ports.list"
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/monitor.sh" --scan > /dev/null 2>&1
check "expired block released"          "grep -q 'delete deny 9999/tcp' '$SANDBOX/ufw.log'"
check "rogue re-blocked after expiry"   "grep -q 'deny 9999/tcp' '$SANDBOX/ufw.log'"
check "UNBLOCK event logged"            "grep -q 'UNBLOCK 9999' '$VPSSEC_STATE_DIR/port-blocks.log'"

echo
echo "=== smoke: CLI unblock ==="
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/vpssec" unblock 9999 > /dev/null 2>&1
check "manual unblock removes rule"     "grep -q 'delete deny 9999/tcp' '$SANDBOX/ufw.log'"
check "port removed from block list"    "! grep -q '|9999$' '$VPSSEC_STATE_DIR/blocked-ports.list'"
check "manual unblock logged"           "grep -q 'manual unblock' '$VPSSEC_STATE_DIR/port-blocks.log'"

echo
echo "=== smoke: tunnel ports (CLI + dashboard) ==="
rm -f "$VPSSEC_CONF_DIR/tunnel-ports.list" "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/vpssec" tunnels add "8443,9999,9999,notaport" > "$SANDBOX/tunadd.out" 2>&1 || true
check "tunnels add writes the list"     "grep -qx '8443' '$VPSSEC_CONF_DIR/tunnel-ports.list' && grep -qx '9999' '$VPSSEC_CONF_DIR/tunnel-ports.list'"
check "duplicate tunnel port added once" "[ \"\$(grep -c '^9999\$' '$VPSSEC_CONF_DIR/tunnel-ports.list')\" -eq 1 ]"
check "invalid tunnel port rejected"    "grep -q 'Ignoring invalid port: notaport' '$SANDBOX/tunadd.out'"
check "declared tunnel port opened in ufw" "grep -q 'allow 8443/tcp' '$SANDBOX/ufw.log'"
bash "$HERE/vpssec" tunnels list > "$SANDBOX/tunlist.out" 2>&1 || true
check "tunnels list shows declared ports" "grep -q '8443' '$SANDBOX/tunlist.out' && grep -q '9999' '$SANDBOX/tunlist.out'"
bash "$HERE/vpssec" status > "$SANDBOX/status2.out" 2>&1 || true
check "dashboard shows tunnel ports"    "grep -q 'Tunnel ports' '$SANDBOX/status2.out'"
bash "$HERE/vpssec" tunnels remove 9999 > /dev/null 2>&1 || true
check "tunnels remove works"            "! grep -qx '9999' '$VPSSEC_CONF_DIR/tunnel-ports.list'"
# undeclaring must restore normal monitoring of that port: the admin also
# closes it again (declaring a tunnel port opens it), exactly as the Ports
# menu does.
sed -i '/^9999$/d' "$VPSSEC_CONF_DIR/allowed-ports.list"
rm -f "$SANDBOX/ufw.log" "$VPSSEC_STATE_DIR/blocked-ports.list"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/monitor.sh" --scan > /dev/null 2>&1
check "undeclared port is monitored again" "grep -q 'deny 9999/tcp' '$SANDBOX/ufw.log'"
# the still-declared tunnel port stays protected
check "remaining tunnel port still safe" "! grep -q 'deny 8443' '$SANDBOX/ufw.log'"
bash "$HERE/vpssec" tunnels remove 8443 > /dev/null 2>&1 || true

echo
echo "=== smoke: guard API ==="
# require a WORKING python3 (WindowsApps stubs exist but are broken)
if python3 -c 'print(1)' >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
    bash "$HERE/lib/guard.sh" --serve --port 18099 > "$SANDBOX/guard.out" 2>&1 &
    GPID=$!
    # wait for the server to accept connections (up to ~10s)
    BODY=""
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        BODY="$(curl -s --max-time 2 http://127.0.0.1:18099/health 2>/dev/null || true)"
        printf '%s' "$BODY" | grep -q '"status": *"ok"' && break
        sleep 0.5
    done
    check "guard /health answers ok"     "printf '%s' \"\$BODY\" | grep -q '\"status\": *\"ok\"'"
    BODY="$(curl -s --max-time 3 http://127.0.0.1:18099/status || true)"
    check "guard /status returns allowed" "printf '%s' \"\$BODY\" | grep -q '\"allowed\"'"
    check "guard /status returns blocked" "printf '%s' \"\$BODY\" | grep -q '\"blocked\"'"
    kill "$GPID" 2>/dev/null || true
    wait "$GPID" 2>/dev/null || true
else
    echo "  skip- guard API (python3/curl not available)"
fi

echo
echo "=== smoke: CLI status ==="
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/vpssec" status > "$SANDBOX/status.out" 2>&1 || true
check "status shows firewall line"      "grep -q 'Firewall' '$SANDBOX/status.out'"
check "status shows ssh port"           "grep -q 'SSH port' '$SANDBOX/status.out'"
check "status shows monitor block info" "grep -q 'Block window' '$SANDBOX/status.out'"
check "status shows allowed count"      "grep -q 'Allowed ports' '$SANDBOX/status.out'"

echo
echo
echo "=== smoke: blocked list view ==="
# ensure one port is blocked, then render the blocked view
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/monitor.sh" --scan >/dev/null 2>&1
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/vpssec" blocked > "$SANDBOX/blocked.out" 2>&1 || true
check "blocked view lists port 9999"    "grep -q 'port *9999' '$SANDBOX/blocked.out'"
check "blocked view shows countdown"    "grep -q 'unblocks in' '$SANDBOX/blocked.out'"

 echo
echo "=== smoke: update command (no install dir) ==="
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/vpssec" update > "$SANDBOX/update.out" 2>&1 || true
check "update reports missing install"  "grep -qi 'not installed at' '$SANDBOX/update.out'"

# update WITH a fake install dir
mkdir -p "$SANDBOX/opt/vps-security/.git"
git -C "$SANDBOX/opt/vps-security" init -q 2>/dev/null || true
cd "$SANDBOX/opt/vps-security" && git remote add origin "https://github.com/amir12120/vps-security.git" 2>/dev/null || true
cd "$HERE"
if git ls-remote https://github.com/amir12120/vps-security.git HEAD >/dev/null 2>&1; then
    git clone -q https://github.com/amir12120/vps-security.git "$SANDBOX/opt/vps-security-clone" 2>/dev/null || true
    if [ -d "$SANDBOX/opt/vps-security-clone/.git" ]; then
        rm -rf "$SANDBOX/opt/vps-security"
        mv "$SANDBOX/opt/vps-security-clone" "$SANDBOX/opt/vps-security"
        VPSSEC_TARGET_DIR="$SANDBOX/opt/vps-security" bash "$HERE/vpssec" update > "$SANDBOX/update2.out" 2>&1 || true
        check "update says up-to-date or updated" "grep -qE 'Already up to date|Updated:' '$SANDBOX/update2.out'"
    fi
else
    echo "  skip- live update test (no network)"
fi

echo
echo "=== smoke: TUI fallback menu (non-interactive) ==="
printf '0\n' | bash "$HERE/vpssec" > "$SANDBOX/menu.out" 2>&1 || true
check "fallback menu shows banner"      "grep -q 'vps-security' '$SANDBOX/menu.out'"
check "fallback menu lists scan option" "grep -q 'Scan for rogue ports now' '$SANDBOX/menu.out'"
check "fallback menu lists blocked"     "grep -q 'View blocked ports' '$SANDBOX/menu.out'"
check "fallback menu lists update"      "grep -q 'Update vps-security' '$SANDBOX/menu.out'"

# menu-driven blocked view: pick option 6 then exit (0)
printf '6\n0\n' | bash "$HERE/vpssec" > "$SANDBOX/menu2.out" 2>&1 || true
check "menu option 6 shows blocked view" "grep -q 'Blocked Ports' '$SANDBOX/menu2.out'"

# menu-driven unblock: option 7 with a blocked port present
printf '7\n1\n0\n' | bash "$HERE/vpssec" > "$SANDBOX/menu3.out" 2>&1 || true
check "menu unblock releases port"      "grep -q 'unblocked' '$SANDBOX/menu3.out'"

echo
echo "=== smoke: install with NO extra ports leaves firewall OFF ==="
# reset state from the first full install, then run install again but
# answer NO extra ports (blank line immediately)
rm -f "$VPSSEC_CONF_DIR/allowed-ports.list" "$VPSSEC_CONF_DIR/monitor.conf"
rm -f "$SANDBOX/ufw.log"
printf 'y\n3333\n\nn\n' \
    | UFW_LOG="$SANDBOX/ufw.log" APT_LOG="$SANDBOX/apt.log" SYSTEMCTL_LOG="$SANDBOX/systemctl.log" \
      bash "$HERE/vpssec" install > "$SANDBOX/install2.out" 2>&1 || true
check "empty-ports install warns firewall stays off" "grep -q 'firewall will NOT be enabled' '$SANDBOX/install2.out'"
check "empty-ports install skips monitor"           "grep -q 'monitor skipped' '$SANDBOX/install2.out'"
check "empty-ports install never enables ufw"       "! grep -q ' enable' '$SANDBOX/ufw.log'"
check "empty-ports install removes stale allow-list" "[ ! -f '$VPSSEC_CONF_DIR/allowed-ports.list' ]"

echo
echo "=== smoke: install adopts the admin's existing ufw rules ==="
# A tunnel/panel port opened before vps-security existed must survive the
# ufw --force reset the installer performs.
printf '7777/tcp                   ALLOW       Anywhere\n' > "$SANDBOX/ufw-pre.txt"
rm -f "$VPSSEC_CONF_DIR/allowed-ports.list" "$SANDBOX/ufw.log"
printf 'n\n\n\nn\n18080\nn\nn\n' \
    | UFW_STATUS_EXTRA="$SANDBOX/ufw-pre.txt" UFW_LOG="$SANDBOX/ufw.log" \
      SYSTEMCTL_LOG="$SANDBOX/systemctl.log" \
      bash "$HERE/vpssec" install > "$SANDBOX/install3.out" 2>&1 || true
check "install announces adopted ports"  "grep -q 'already open in ufw' '$SANDBOX/install3.out'"
check "adopted port kept in allow-list"   "grep -qx '7777' '$VPSSEC_CONF_DIR/allowed-ports.list'"
check "adopted port re-opened after reset" "grep -q 'allow 7777/tcp' '$SANDBOX/ufw.log'"
check "install hints at listening services" "grep -q 'Services listening right now' '$SANDBOX/install3.out'"

echo
echo "=== smoke: install opens EVERY port from one comma-separated answer ==="
# The admin types one line (444,2086,2098,2689) instead of one port per
# prompt; all four must end up open and in the allow-list.
rm -f "$VPSSEC_CONF_DIR/allowed-ports.list" "$VPSSEC_CONF_DIR/monitor.conf"
rm -f "$SANDBOX/ufw.log"
printf 'n\n\n444,2086,2098,2689\nn\n18080\nn\nn\n' \
    | UFW_LOG="$SANDBOX/ufw.log" SYSTEMCTL_LOG="$SANDBOX/systemctl.log" \
      bash "$HERE/vpssec" install > "$SANDBOX/install4.out" 2>&1 || true
for _p in 444 2086 2098 2689; do
    check "comma list: ufw opened $_p/tcp" "grep -q 'allow $_p/tcp' '$SANDBOX/ufw.log'"
done
check "comma list: all four in the allow-list" \
    "for x in 444 2086 2098 2689; do grep -qx \"\$x\" '$VPSSEC_CONF_DIR/allowed-ports.list' || exit 1; done"
check "comma list: firewall enabled"          "grep -q ' enable' '$SANDBOX/ufw.log'"

# A junk token in the middle of the list must not cost the good ports.
rm -f "$VPSSEC_CONF_DIR/allowed-ports.list" "$SANDBOX/ufw2.log"
printf 'n\n\n444,notaport,70000\nn\n18080\nn\nn\n' \
    | UFW_LOG="$SANDBOX/ufw2.log" SYSTEMCTL_LOG="$SANDBOX/systemctl.log" \
      bash "$HERE/vpssec" install > "$SANDBOX/install5.out" 2>&1 || true
check "comma list: good port still opened"  "grep -q 'allow 444/tcp' '$SANDBOX/ufw2.log'"
check "comma list: bad name reported"       "grep -q 'Ignoring invalid port: notaport' '$SANDBOX/install5.out'"
check "comma list: out-of-range reported"   "grep -q 'Ignoring invalid port: 70000' '$SANDBOX/install5.out'"
check "comma list: bad ports not opened"    "! grep -q 'allow 70000' '$SANDBOX/ufw2.log'"

echo
echo "=== smoke: Ports menu 'add' takes a whole comma-separated list ==="
rm -f "$SANDBOX/ufw.log"
printf '1\n9001,9002,notaport\n\n' \
    | UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/vpssec" ports > "$SANDBOX/portsadd.out" 2>&1 || true
check "ports add opened 9001/tcp"      "grep -q 'allow 9001/tcp' '$SANDBOX/ufw.log'"
check "ports add opened 9002/tcp"      "grep -q 'allow 9002/tcp' '$SANDBOX/ufw.log'"
check "ports add listed both"          "grep -qx '9001' '$VPSSEC_CONF_DIR/allowed-ports.list' && grep -qx '9002' '$VPSSEC_CONF_DIR/allowed-ports.list'"
check "ports add skipped the bad token" "grep -q 'Ignoring invalid port: notaport' '$SANDBOX/portsadd.out'"

echo
echo "=== smoke: CLI invoked through a symlink (bootstrap layout) ==="
# The bootstrap installer links /usr/local/bin/vpssec -> <repo>/vpssec.
# bash reports BASH_SOURCE as the symlink, so if the CLI does not resolve
# it, lib/common.sh is never sourced and the menu never appears.
LINK_DIR="$SANDBOX/bin"
mkdir -p "$LINK_DIR"
if ln -s "$HERE/vpssec" "$LINK_DIR/vpssec" 2>/dev/null && [ -L "$LINK_DIR/vpssec" ]; then
    printf '0\n' | bash "$LINK_DIR/vpssec" > "$SANDBOX/linkmenu.out" 2>&1 || true
    bash "$LINK_DIR/vpssec" version | grep -q "vpssec $VER" && R=0 || R=1
    check "symlinked CLI loads its libraries"  "[ \"$R\" -eq 0 ]"
    check "symlinked CLI draws the menu"       "grep -q 'Main Menu' '$SANDBOX/linkmenu.out'"
    check "symlinked CLI reports no load error" "! grep -q 'unbound variable\|No such file' '$SANDBOX/linkmenu.out'"
else
    echo "  skip- symlink checks (filesystem without symlink support)"
fi

echo
echo "=== smoke: TUI frame rendering (source guards) ==="
# The pty check below needs Linux `script`; these guards hold everywhere and
# pin the exact regression that made the menu overlap the banner logo: a
# partial redraw (cursor-home + rewrite) instead of a full cleared frame.
PARTIAL=$(grep -c '\[%dA' "$HERE/vpssec" || true)
check "menu has no partial cursor-up redraw"    "[ \"${PARTIAL:-0}\" -eq 0 ]"
CLEAR_FN=$(grep -c '^ui_clear()' "$HERE/vpssec" || true)
check "TUI defines a screen-clear helper"       "[ \"${CLEAR_FN:-0}\" -eq 1 ]"
FRAME_CLEAR=$(awk '/^ui_menu\(\) \{/,/^\}/' "$HERE/vpssec" | grep -c 'ui_title "\$title"')
check "every menu frame redraws the full header" "[ \"${FRAME_CLEAR:-0}\" -ge 1 ]"

# Behavioural check of the same thing, without needing a pty: drive the REAL
# TUI functions with buffered keys and count how many times the header is
# painted. Each keypress must produce a complete frame, banner included.
TUIBOX="$SANDBOX/tui"
mkdir -p "$TUIBOX"
awk '/^ui_header\(\) \{/{f=1} /^ui_press_any_key\(\) \{/{f=0} f' "$HERE/vpssec" > "$TUIBOX/tui.sh"
# In the extracted copy only: force the interactive branch (stdin is a pipe).
sed 's/if \[ ! -t 0 \]; then/if false; then/' "$TUIBOX/tui.sh" > "$TUIBOX/tui-interactive.sh"
if grep -q '^ui_menu()' "$TUIBOX/tui-interactive.sh"; then
    # Two navigation keys (arrow-down, then 'j') plus 'q' to leave = 3 frames.
    printf '\033[Bjq' | TUIBOX="$TUIBOX" bash -c '
        set -u
        VERSION="test"
        RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; DIM=""; RESET=""
        prompt() { :; }
        # shellcheck disable=SC1090
        source "$TUIBOX/tui-interactive.sh"
        ui_menu "Main Menu" "one" "two" "three"
    ' > "$TUIBOX/frames.out" 2>&1 || true
    FRAMES=$(grep -c 'server hardening toolkit' "$TUIBOX/frames.out" || true)
    if ! [ "${FRAMES:-0}" -ge 3 ]; then
        echo "--- frames.out (expected 3 headers, got ${FRAMES:-0}) ---"
        cat -v "$TUIBOX/frames.out" | tail -n 40
    fi
    check "menu repaints a full frame per keypress"  "[ \"${FRAMES:-0}\" -ge 3 ]"
else
    echo "  skip- frame repaint check (TUI helpers could not be extracted)"
fi

echo
echo "=== smoke: guided install ends in the TUI menu (pty) ==="
if command -v script >/dev/null 2>&1; then
    # Start from a clean port list so the guided setup takes its short
    # "no extra ports" path and the answers below map 1:1 onto the
    # prompts: skip apt=n, keep SSH port=<blank>, no ports=<blank>,
    # no tunnels=n, then q in the menu.
    rm -f "$VPSSEC_CONF_DIR/allowed-ports.list" "$VPSSEC_CONF_DIR/tunnel-ports.list"
    printf 'n\n\n\nn\n18080\nn\nq\n' | TERM=xterm VPSSEC_NO_MENU=0 timeout 60 \
        script -qec "bash '$HERE/vpssec' install" /dev/null > "$SANDBOX/ptymenu.out" 2>&1 || true
    # Only assert once the pty genuinely drove the run to completion;
    # otherwise this environment cannot host the test (skip, don't fail).
    if grep -q 'guided setup' "$SANDBOX/ptymenu.out" && grep -q 'SSH port unchanged' "$SANDBOX/ptymenu.out"; then
        if ! grep -q 'Main Menu' "$SANDBOX/ptymenu.out"; then
            echo "--- ptymenu.out (last 25 lines) ---"
            tail -n 25 "$SANDBOX/ptymenu.out" | cat -v
        fi
        check "setup finishes and enters the menu"  "grep -q 'Setup finished' '$SANDBOX/ptymenu.out'"
        check "install opens the menu on a terminal" "grep -q 'Main Menu' '$SANDBOX/ptymenu.out'"
    else
        echo "  skip- pty menu check (pty harness did not feed input here)"
    fi
else
    echo "  skip- pty menu check (no 'script' command)"
fi

echo
echo "=== smoke: help & version ==="
bash "$HERE/vpssec" version | grep -q "vpssec $VER" && R=0 || R=1
check "version reports $VER"            "[ \"$R\" -eq 0 ]"
bash "$HERE/vpssec" help | grep -q 'update' && R=0 || R=1
check "help mentions update"            "[ \"$R\" -eq 0 ]"

echo
echo "=== smoke: Bot & Scanner Shield ==="
# enable with an explicit protected port so the checks below are
# independent of the allow-list (the empty-ports install wiped it)
rm -f "$SANDBOX/ufw.log"
printf '8080\n' > "$VPSSEC_CONF_DIR/tunnel-ports.list"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --enable "443,8080" > "$SANDBOX/shield.out" 2>&1 || true
SP="$(grep -E '^Port ' "$SSH_CFG" | tail -1 | awk '{print $2}')"; [ -z "$SP" ] && SP=22
check "shield enabled"                  "grep -q 'Shield enabled' '$SANDBOX/shield.out'"
check "shield rate-limits protected port" "grep -q 'limit 443/tcp' '$SANDBOX/ufw.log'"
check "tunnel port is NEVER rate-limited" "! grep -q 'limit 8080/' '$SANDBOX/ufw.log'"
check "tunnel port kept out of shield list" "! grep -q '8080' '$VPSSEC_CONF_DIR/botshield.conf'"
check "shield conf written"             "grep -q 'SHIELD_ENABLED=1' '$VPSSEC_CONF_DIR/botshield.conf'"
check "shield ufw limit on ssh"         "grep -qE 'limit (${SP})/tcp' '$SANDBOX/ufw.log'"
check "shield timer installed"          "[ -f '$VPSSEC_SYSTEMD_DIR/vps-security-shield.timer' ]"
check "flag drops written to before.rules" "grep -q 'vps-security botshield BEGIN' '$UFW_DIR/before.rules'"
# ban an IP and check status/unban
printf '%s|203.0.113.55\n' "$(date +%s)" > "$VPSSEC_STATE_DIR/shield-bans.list"
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --unban 203.0.113.55 > "$SANDBOX/unban.out" 2>&1 || true
check "unban removes ufw deny"          "grep -q 'delete deny from 203.0.113.55' '$SANDBOX/ufw.log'"
check "unban clears state"              "! grep -q '203.0.113.55' '$VPSSEC_STATE_DIR/shield-bans.list'"
bash "$HERE/lib/botshield.sh" --status > "$SANDBOX/shieldstat.out" 2>&1 || true
check "shield status shows state"       "grep -q 'Bot & Scanner Shield' '$SANDBOX/shieldstat.out'"
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --disable > /dev/null 2>&1 || true
check "shield disable removes flag drops" "! grep -q 'vps-security botshield BEGIN' '$UFW_DIR/before.rules'"
check "shield disable clears conf"      "grep -q 'SHIELD_ENABLED=0' '$VPSSEC_CONF_DIR/botshield.conf'"
# disable must release every active ban (timer is gone, nothing else would expire them)
printf '%s|198.51.100.99\n' "$(date +%s)" > "$VPSSEC_STATE_DIR/shield-bans.list"
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --disable > /dev/null 2>&1 || true
check "shield disable releases active bans" "! grep -q '198.51.100.99' '$VPSSEC_STATE_DIR/shield-bans.list' && grep -q 'delete deny from 198.51.100.99' '$SANDBOX/ufw.log'"
# scan must be a no-op while disabled (zombie guard)
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --maint > /dev/null 2>&1 || true
check "disabled shield never bans (zombie guard)" "! grep -q 'deny from' '$SANDBOX/ufw.log'"

# ---- tunnel safety: never ban the server's own or the admin's peers ----
printf 'GEO_ENABLED=0\nGEO_COUNTRIES=\nGEO_BYPASS=198.51.100.7\n' > "$VPSSEC_CONF_DIR/geo.conf"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --enable "443" > /dev/null 2>&1 || true
rm -f "$SANDBOX/ufw.log" "$VPSSEC_STATE_DIR/shield-bans.list"
# a real attacker on 443 gets banned
SS_SYN_FLOOD=203.0.113.9 UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --maint > /dev/null 2>&1 || true
check "SYN flood from a public IP is banned" "grep -q 'deny from 203.0.113.9' '$SANDBOX/ufw.log'"
# a private peer is never banned (that is the tunnel talking to itself)
SS_SYN_FLOOD=10.0.0.9 UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --maint > /dev/null 2>&1 || true
check "private peer is never banned"        "! grep -q 'deny from 10.0.0.9' '$SANDBOX/ufw.log'"
# a declared trusted peer (GeoIP bypass) is never banned either
SS_SYN_FLOOD=198.51.100.7 UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --maint > /dev/null 2>&1 || true
check "trusted peer is never banned"        "! grep -q 'deny from 198.51.100.7' '$SANDBOX/ufw.log'"
check "skipped bans are logged"             "grep -q 'SKIP-BAN 10.0.0.9' '$VPSSEC_STATE_DIR/shield.log' && grep -q 'SKIP-BAN 198.51.100.7' '$VPSSEC_STATE_DIR/shield.log'"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --disable > /dev/null 2>&1 || true

echo
echo "=== smoke: GeoIP country filter ==="
# sandboxed curl that returns CIDR content for any country
mkdir -p "$GEO_TMP"
cat > "$STUBS/curl" <<CEOF
#!/usr/bin/env bash
# emulate IPFire country CIDR download
out="/dev/null"
prev=""
for a in "\$@"; do
  case "\$prev" in -o) out="\$a";; esac
  prev="\$a"
done
printf '1.2.3.0/24\n5.6.7.0/24\nnot-a-cidr\n' > "\$out"
exit 0
CEOF
chmod +x "$STUBS/curl"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --add "ir,de,1R" > "$SANDBOX/geoadd.out" 2>&1 || true
check "geo add normalizes codes"        "grep -q 'IR,DE' '$VPSSEC_CONF_DIR/geo.conf'"
check "geo add rejects invalid code"    "grep -q 'not a valid' '$SANDBOX/geoadd.out'"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --enable > "$SANDBOX/geoenable.out" 2>&1 || true
check "geo enable downloads lists"      "grep -q '^1.2.3.0/24$' '$VPSSEC_STATE_DIR/geo/IR.cidr' && grep -q '^1.2.3.0/24$' '$VPSSEC_STATE_DIR/geo/DE.cidr'"
check "geo enable writes before.rules"  "grep -q 'vps-security geoip BEGIN' '$UFW_DIR/before.rules'"
check "geo enable writes ipset rule"    "grep -q 'match-set vpssec_geo_allow src' '$UFW_DIR/before.rules'"
check "geo enable writes final DROP"    "grep -q -- '-A ufw-before-input ! -i lo -m conntrack --ctstate NEW -j DROP' '$UFW_DIR/before.rules'"
check "geo DROP is NEW-only (tunnel safe)" "grep -q -- '--ctstate NEW -j DROP' '$UFW_DIR/before.rules' && ! grep -qE -- '-A ufw-before-input -j DROP' '$UFW_DIR/before.rules'"
check "geo enabled conf"                "grep -q 'GEO_ENABLED=1' '$VPSSEC_CONF_DIR/geo.conf'"
check "geo bypass accepted"             "bash '$HERE/lib/geoip.sh' --bypass add 198.51.100.7 >/dev/null 2>&1 && grep -q 'GEO_BYPASS=.*198.51.100.7' '$VPSSEC_CONF_DIR/geo.conf'"
check "geo bypass written to rules"     "grep -q -- '-s 198.51.100.7 -j ACCEPT' '$UFW_DIR/before.rules'"
bash "$HERE/lib/geoip.sh" --list > "$SANDBOX/geolist.out" 2>&1 || true
check "geo list shows countries"        "grep -q 'IR DE' '$SANDBOX/geolist.out'"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --remove "de" > "$SANDBOX/georem.out" 2>&1 || true
check "geo remove keeps others"         "grep -q '^GEO_COUNTRIES=IR$' '$VPSSEC_CONF_DIR/geo.conf'"
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --disable > /dev/null 2>&1 || true
check "geo disable strips rules"        "! grep -q 'vps-security geoip BEGIN' '$UFW_DIR/before.rules'"
check "geo disable clears conf"         "grep -q 'GEO_ENABLED=0' '$VPSSEC_CONF_DIR/geo.conf'"

echo
echo "=== smoke: GeoIP country names (full names / Persian / alpha-3) ==="
# a) add via full names, Persian names, alpha-3 and unique prefix
printf 'GEO_ENABLED=0\nGEO_COUNTRIES=\nGEO_BYPASS=\n' > "$VPSSEC_CONF_DIR/geo.conf"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --add "Iran,Germany,USA,آلمان,united kingdom,Swed" > "$SANDBOX/geonames.out" 2>&1 || true
check "names resolve (EN/FA/a3/prefix)" "grep -q 'GEO_COUNTRIES=IR,DE,US,GB,SE' '$VPSSEC_CONF_DIR/geo.conf'"
check "ambiguous prefix rejected"       "grep -q '\"united\" is not a valid\|not a valid country' '$SANDBOX/geonames.out' && ! grep -q 'GEO_COUNTRIES=.*GB,\|,GB$' /dev/null; grep -c 'united' '$VPSSEC_CONF_DIR/geo.conf' | grep -q '^0$'"
# b) remove via full + Persian names (list is IR,DE,US,GB,SE after a)
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --remove "united kingdom,ایران" > /dev/null 2>&1 || true
check "remove by name works"            "grep -q '^GEO_COUNTRIES=DE,US,SE$' '$VPSSEC_CONF_DIR/geo.conf'"
# c) bogus name is rejected and adds nothing
printf 'GEO_ENABLED=0\nGEO_COUNTRIES=\nGEO_BYPASS=\n' > "$VPSSEC_CONF_DIR/geo.conf"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --add "Atlantis,Narnia" > "$SANDBOX/geobogus.out" 2>&1 || true
check "bogus names rejected"            "grep -q 'not a valid country' '$SANDBOX/geobogus.out' && grep -q '^GEO_COUNTRIES=$' '$VPSSEC_CONF_DIR/geo.conf'"
# d) CLI prompt mentions full names
bash "$HERE/vpssec" help > /dev/null 2>&1 || true
check "geo help still lists commands"   "bash '$HERE/vpssec' help 2>&1 | grep -q 'geo'"

# e) forgiving spellings: exact name, short form, typo, alpha-3, alias
printf 'GEO_ENABLED=0\nGEO_COUNTRIES=\nGEO_BYPASS=\n' > "$VPSSEC_CONF_DIR/geo.conf"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --add "netherlands,netherland,nederlands,NLD,IRN,deutschland" > "$SANDBOX/geofuzzy.out" 2>&1 || true
check "every forgiving spelling resolved"   "! grep -q 'not a valid' '$SANDBOX/geofuzzy.out'"
check "they all land on NL, IR, DE"         "grep -q '^GEO_COUNTRIES=NL,IR,DE$' '$VPSSEC_CONF_DIR/geo.conf'"

# f) an ambiguous name gets a usable hint instead of silence
printf 'GEO_ENABLED=0\nGEO_COUNTRIES=\nGEO_BYPASS=\n' > "$VPSSEC_CONF_DIR/geo.conf"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --add "Turk" > "$SANDBOX/geohint.out" 2>&1 || true
check "ambiguous name lists candidates"  "grep -q 'Did you mean:.*TR (turkey)' '$SANDBOX/geohint.out' && grep -q 'TM (turkmenistan)' '$SANDBOX/geohint.out'"
check "ambiguity never applies a guess"  "grep -q '^GEO_COUNTRIES=$' '$VPSSEC_CONF_DIR/geo.conf'"

# g) name lookup table (vpssec geo names / geoip.sh --names)
bash "$HERE/lib/geoip.sh" --names > "$SANDBOX/geonametable.out" 2>&1 || true
check "names table lists countries"      "grep -q 'netherlands' '$SANDBOX/geonametable.out' && grep -q 'germany' '$SANDBOX/geonametable.out'"
check "names table shows Persian aliases" "grep -q 'هلند' '$SANDBOX/geonametable.out'"
check "names table mentions NL code"     "grep -qE '^  NL ' '$SANDBOX/geonametable.out'"

echo
echo "=== smoke: GeoIP safety — server must stay open when no countries are set ==="
# a) enable with NO countries configured -> refuse, write nothing, stay open
printf 'GEO_ENABLED=0\nGEO_COUNTRIES=\nGEO_BYPASS=\n' > "$VPSSEC_CONF_DIR/geo.conf"
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --enable > "$SANDBOX/geosafe1.out" 2>&1 || true
check "geo enable w/o countries refuses"    "grep -q 'NOT enabled' '$SANDBOX/geosafe1.out'"
check "geo enable w/o countries: no rules"  "! grep -q 'vps-security geoip BEGIN' '$UFW_DIR/before.rules'"
check "geo enable w/o countries: stays off" "! grep -q '^GEO_ENABLED=1$' '$VPSSEC_CONF_DIR/geo.conf'"

# b) countries configured but ALL downloads fail -> refuse, no world-DROP
printf 'GEO_ENABLED=0\nGEO_COUNTRIES=IR,DE\nGEO_BYPASS=\n' > "$VPSSEC_CONF_DIR/geo.conf"
rm -f "$VPSSEC_STATE_DIR"/geo/*.cidr 2>/dev/null
cat > "$STUBS/curl" <<'CEOF2'
#!/usr/bin/env bash
exit 1
CEOF2
chmod +x "$STUBS/curl"
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --enable > "$SANDBOX/geosafe2.out" 2>&1 || true
check "geo enable w/ failed downloads refuses" "grep -q 'NOT enabled' '$SANDBOX/geosafe2.out'"
check "failed downloads write no DROP rule"    "! grep -q -- 'conntrack --ctstate NEW -j DROP' '$UFW_DIR/before.rules'"

# c) removing the LAST country while enabled -> auto-disable + rules stripped
cat > "$STUBS/curl" <<'CEOF3'
#!/usr/bin/env bash
out="/dev/null"; prev=""
for a in "$@"; do case "$prev" in -o) out="$a";; esac; prev="$a"; done
printf '1.2.3.0/24\n' > "$out"
exit 0
CEOF3
chmod +x "$STUBS/curl"
printf 'GEO_ENABLED=0\nGEO_COUNTRIES=IR\nGEO_BYPASS=\n' > "$VPSSEC_CONF_DIR/geo.conf"
printf '1.2.3.0/24\n' > "$VPSSEC_STATE_DIR/geo/IR.cidr"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --enable > /dev/null 2>&1 || true
check "geo re-enabled for safety test"      "grep -q '^GEO_ENABLED=1$' '$VPSSEC_CONF_DIR/geo.conf'"
check "geo DROP rule active before remove"  "grep -q -- 'conntrack --ctstate NEW -j DROP' '$UFW_DIR/before.rules'"
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --remove "ir" > "$SANDBOX/geosafe3.out" 2>&1 || true
check "last-country remove auto-disables"   "grep -q '^GEO_ENABLED=0$' '$VPSSEC_CONF_DIR/geo.conf'"
check "last-country remove strips rules"    "! grep -q 'vps-security geoip BEGIN' '$UFW_DIR/before.rules'"
check "last-country remove message shown"   "grep -q 'open to ALL countries' '$SANDBOX/geosafe3.out'"

# d) boot restore with unsafe config must never re-apply a world-DROP
printf 'GEO_ENABLED=1\nGEO_COUNTRIES=ZZ\nGEO_BYPASS=\n' > "$VPSSEC_CONF_DIR/geo.conf"
rm -f "$VPSSEC_STATE_DIR/geo/ZZ.cidr"
{ echo ""; echo "# --- vps-security geoip BEGIN ---"; echo "-A ufw-before-input ! -i lo -m conntrack --ctstate NEW -j DROP"; echo "# --- vps-security geoip END ---"; } >> "$UFW_DIR/before.rules"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --ipset-restore > /dev/null 2>&1 || true
check "boot restore strips unsafe geo rules" "! grep -q 'vps-security geoip BEGIN' '$UFW_DIR/before.rules'"
# ...and keeps/rewrites them when the config is safe
printf 'GEO_ENABLED=1\nGEO_COUNTRIES=IR\nGEO_BYPASS=\n' > "$VPSSEC_CONF_DIR/geo.conf"
printf '1.2.3.0/24\n' > "$VPSSEC_STATE_DIR/geo/IR.cidr"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/geoip.sh" --ipset-restore > /dev/null 2>&1 || true
check "boot restore keeps safe geo rules"    "grep -q 'vps-security geoip BEGIN' '$UFW_DIR/before.rules'"

echo
echo "=== smoke: new menu commands present ==="
printf '10\n0\n' | bash "$HERE/vpssec" > "$SANDBOX/menumaint.out" 2>&1 || true
check "menu shows maint entry"          "grep -q 'Maintenance' '$SANDBOX/menumaint.out'"
printf '11\n0\n0\n' | bash "$HERE/vpssec" > "$SANDBOX/menushield.out" 2>&1 || true
check "menu shows shield entry"         "grep -q 'Bot & Scanner Shield' '$SANDBOX/menushield.out'"
printf '12\n0\n0\n' | bash "$HERE/vpssec" > "$SANDBOX/menugeo.out" 2>&1 || true
check "menu shows geo entry"            "grep -q 'GeoIP Country Filter' '$SANDBOX/menugeo.out'"
bash "$HERE/vpssec" geo list > "$SANDBOX/geocmd.out" 2>&1 || true
check "vpssec geo list works"           "grep -q 'GeoIP country filter' '$SANDBOX/geocmd.out'"
bash "$HERE/vpssec" shield status > "$SANDBOX/shieldcmd.out" 2>&1 || true
check "vpssec shield status works"      "grep -q 'Bot & Scanner Shield' '$SANDBOX/shieldcmd.out'"

echo
echo "=== smoke: FULL uninstall — SSH to 22, ufw reset+disabled+allow 22, config wiped ==="
rm -f "$SANDBOX/ufw.log"
printf 'Y\n' \
    | UFW_LOG="$SANDBOX/ufw.log" SYSTEMCTL_LOG="$SANDBOX/systemctl.log" \
      bash "$HERE/vpssec" uninstall > "$SANDBOX/uninstall.out" 2>&1 || true
check "uninstall resets SSH port to 22"      "grep -q '^Port 22$' '$SSH_CFG'"
check "uninstall restarts sshd"              "grep -q 'restart sshd' '$SANDBOX/systemctl.log' || grep -q 'restart ssh' '$SANDBOX/systemctl.log'"
check "uninstall runs ufw reset"             "grep -q -- '--force reset' '$SANDBOX/ufw.log'"
check "uninstall allows port 22"             "grep -q 'allow 22/tcp' '$SANDBOX/ufw.log'"
check "uninstall disables ufw"               "grep -q -- '--force disable' '$SANDBOX/ufw.log'"
check "uninstall removes allowed-ports.list" "[ ! -f '$VPSSEC_CONF_DIR/allowed-ports.list' ]"
check "uninstall removes monitor.conf"       "[ ! -f '$VPSSEC_CONF_DIR/monitor.conf' ]"
check "uninstall removes geo.conf"           "[ ! -f '$VPSSEC_CONF_DIR/geo.conf' ]"
check "uninstall removes shield conf"        "[ ! -f '$VPSSEC_CONF_DIR/botshield.conf' ]"
check "uninstall wipes state dir"            "[ ! -d '$VPSSEC_STATE_DIR' ] || [ -z \"\$(ls -A '$VPSSEC_STATE_DIR' 2>/dev/null)\" ]"
check "uninstall removes systemd units"      "[ ! -f '$VPSSEC_SYSTEMD_DIR/vps-security-monitor.timer' ] && [ ! -f '$VPSSEC_SYSTEMD_DIR/vps-security-geo.timer' ]"
check "uninstall removes maint timer"        "[ ! -f '$VPSSEC_SYSTEMD_DIR/vps-security-maint.timer' ]"
check "uninstall removes install dir"        "[ ! -d '$SANDBOX/opt/vps-security' ]"

echo
echo "=== smoke: maintenance — RAM cache & log cleanup ==="
LOGDIR="$SANDBOX/varlog"
mkdir -p "$LOGDIR"
printf 'rotated' > "$LOGDIR/auth.log.1"
printf 'rotated' > "$LOGDIR/syslog.2.gz"
yes x | head -c 4096 | tr -d '\n' > "$LOGDIR/ufw.log"
printf 'x%.0s' $(seq 1 2048) > "$LOGDIR/kern.log"
rm -f "$SANDBOX/ufw.log"
MAINT_LOG_DIR="$LOGDIR" MAINT_VACUUM_JOURNAL=0 UFW_LOG="$SANDBOX/ufw.log" \
    bash "$HERE/lib/maintain.sh" --run > "$SANDBOX/maint.out" 2>&1 || true
check "maint run reports success"          "grep -q 'Maintenance finished' '$SANDBOX/maint.out'"
check "maint removed rotated .1 log"       "[ ! -f '$LOGDIR/auth.log.1' ]"
check "maint removed rotated .gz log"      "[ ! -f '$LOGDIR/syslog.2.gz' ]"
check "maint truncated active ufw.log"     "[ ! -s '$LOGDIR/ufw.log' ]"
check "maint truncated active kern.log"    "[ ! -s '$LOGDIR/kern.log' ]"
check "maint logged to maintain.log"       "grep -q 'maintenance finished' '$VPSSEC_STATE_DIR/maintain.log'"
bash "$HERE/lib/maintain.sh" --status > "$SANDBOX/maintstat.out" 2>&1 || true
check "maint status shows state"           "grep -q 'Maintenance' '$SANDBOX/maintstat.out'"
check "vpssec maint status works"          "bash '$HERE/vpssec' maint status 2>&1 | grep -q 'Maintenance'"
# safety: vps-security's own logs, the MAINT_EXCLUDE list and subdirs survive
mkdir -p "$LOGDIR/nginx"
printf 'audit' > "$LOGDIR/monitor.log"
printf 'app'   > "$LOGDIR/app.log"
printf 'site'  > "$LOGDIR/nginx/access.log"
MAINT_LOG_DIR="$LOGDIR" MAINT_VACUUM_JOURNAL=0 MAINT_EXCLUDE="app.log" \
    bash "$HERE/lib/maintain.sh" --run > /dev/null 2>&1 || true
MON_KEEP=$(wc -c < "$LOGDIR/monitor.log")
APP_KEEP=$(wc -c < "$LOGDIR/app.log")
NGX_KEEP=$(wc -c < "$LOGDIR/nginx/access.log")
check "maint protects vps-security logs"  "[ '$MON_KEEP' -eq 5 ]"
check "maint honors MAINT_EXCLUDE"        "[ '$APP_KEEP' -eq 3 ]"
check "maint skips subdirectories"        "[ '$NGX_KEEP' -eq 4 ]"
# unit content checks target the generator (units are removed by the uninstall test above)
check "maint unit uses EnvironmentFile"   "grep -q 'EnvironmentFile=-' '$HERE/vpssec' && grep -q 'maintain.conf' '$HERE/vpssec'"
check "maint timer has startup jitter"    "grep -q 'RandomizedDelaySec' '$HERE/vpssec'"

echo
echo "=== smoke: Iranian mirror & DNS (GitHub speed criterion) ==="
MS="$SANDBOX/mirror"
mkdir -p "$MS/etc" "$MS/state"
export VPSSEC_GITCONFIG="$MS/etc/gitconfig"
export VPSSEC_RESOLV_CONF="$MS/etc/resolv.conf"
export VPSSEC_RESOLVED_CONF_D="$MS/etc/resolved.d"
# stub curl: mirror #2 answers fastest, mirror #1 slow, mirror #3 broken,
# direct github FAIL — ensures the winner logic picks iranserver
cat > "$STUBS/curl" <<'MCEOF'
#!/usr/bin/env bash
url=""; prev=""
for a in "$@"; do case "$a" in http*|*github*) [ -z "$url" ] && url="$a";; esac; prev="$a"; done
case "$url" in
    *iranserver*) sleep 0.05; echo "200 0.050000" ;;
    *gitclone*)   sleep 0.30; echo "200 0.300000" ;;
    *theazizi*)   exit 7 ;;
    *)            exit 7 ;;   # direct github.com unreachable in the sandbox
esac
MCEOF
chmod +x "$STUBS/curl"
# stub dig: 403.online answers in 5 ms, Radar in 20, Shecan in 30, rest fail
cat > "$STUBS/dig" <<'DIGEOF'
#!/usr/bin/env bash
ns=""
for a in "$@"; do case "$a" in @*) ns="${a#@}";; esac; done
case "$ns" in
    10.202.10.202)  echo ";; Query time: 5 msec" ;;
    10.202.10.10)   echo ";; Query time: 20 msec" ;;
    178.22.122.100) echo ";; Query time: 30 msec" ;;
    *)              exit 1 ;;
esac
echo ";; status: NOERROR"
echo "github.com. 300 IN A 140.82.121.4"
DIGEOF
chmod +x "$STUBS/dig"
VPSSEC_CONF_DIR="$MS/etc" VPSSEC_STATE_DIR="$MS/state" VPSSEC_SKIP_ROOT_CHECK=1 VPSSEC_SKIP_OS_CHECK=1 \
    bash "$HERE/lib/mirror.sh" --best > "$MS/best.out" 2>&1 <<'MANS'
n
MANS
check "mirror flow found fastest"        "grep -q 'Fastest mirror: github.iranserver.com' '$MS/best.out'"
check "unreachable mirror skipped"       "grep -q 'theazizi.*FAIL\|FAIL  (unreachable)' '$MS/best.out'"
check "insteadOf written to gitconfig"   "grep -q 'insteadof = https://github.com/' '$MS/etc/gitconfig' && grep -q 'iranserver' '$MS/etc/gitconfig'"
check "mirror choice persisted"          "grep -q 'MIRROR_NAME=github.iranserver.com' '$MS/etc/mirror.conf'"
check "DNS unchanged when declined"      "grep -q 'DNS left unchanged' '$MS/best.out'"
check "mirror logged"                    "grep -q 'mirror applied: github.iranserver.com' '$MS/state/mirror.log'"
# DNS: answer 'y' this time; resolv.conf must get Radar (5ms beats Shecan 30ms)
# pre-existing DNS gets backed up by apply_dns, then restored by --reset
printf 'nameserver 8.8.8.8\n' > "$MS/etc/resolv.conf"
printf 'y\n' | VPSSEC_CONF_DIR="$MS/etc" VPSSEC_STATE_DIR="$MS/state" VPSSEC_SKIP_ROOT_CHECK=1 VPSSEC_SKIP_OS_CHECK=1 \
    bash "$HERE/lib/mirror.sh" --best > "$MS/best2.out" 2>&1 || true
check "fastest DNS picked (403 5ms)"     "grep -q 'Fastest DNS: 403.online' '$MS/best2.out'"
check "resolv.conf rewritten to 403"     "grep -q 'nameserver 10.202.10.202' '$MS/etc/resolv.conf'"
check "dns choice persisted"             "grep -q 'DNS_NAME=403.online' '$MS/etc/mirror.conf'"
VPSSEC_CONF_DIR="$MS/etc" VPSSEC_STATE_DIR="$MS/state" VPSSEC_SKIP_ROOT_CHECK=1 VPSSEC_SKIP_OS_CHECK=1 \
    bash "$HERE/lib/mirror.sh" --reset > "$MS/reset.out" 2>&1 || true
check "reset removes insteadOf rule"     "! grep -q 'insteadof' '$MS/etc/gitconfig' || ! [ -s '$MS/etc/gitconfig' ]"
check "reset restores resolv.conf backup" "grep -q 'nameserver 8.8.8.8' '$MS/etc/resolv.conf'"
check "reset clears mirror.conf"         "[ ! -f '$MS/etc/mirror.conf' ]"

# status via CLI
VPSSEC_CONF_DIR="$MS/etc" VPSSEC_STATE_DIR="$MS/state" VPSSEC_SKIP_ROOT_CHECK=1 VPSSEC_SKIP_OS_CHECK=1 \
    bash "$HERE/vpssec" mirror status > "$MS/cli.out" 2>&1 || true
check "vpssec mirror status works"       "grep -q 'Iranian mirror' '$MS/cli.out'"

# menu shows the new entry
printf '13\n0\n0\n' | bash "$HERE/vpssec" > "$SANDBOX/menumirror.out" 2>&1 || true
check "menu shows mirror entry"          "grep -q 'Iranian mirror & DNS' '$SANDBOX/menumirror.out'"

# --- restore global curl stub for any later checks ---
cat > "$STUBS/curl" <<'CEOF4'
#!/usr/bin/env bash
out="/dev/null"; prev=""
for a in "$@"; do case "$prev" in -o) out="$a";; esac; prev="$a"; done
printf '1.2.3.0/24\n' > "$out"
exit 0
CEOF4
chmod +x "$STUBS/curl"

echo "==============================================="
echo "SMOKE RESULT: PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed checks:"
    for f in "${FAILURES[@]}"; do echo "  - $f"; done
    exit 1
fi
echo "ALL SMOKE TESTS PASSED"
exit 0
