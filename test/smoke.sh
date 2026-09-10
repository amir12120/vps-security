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
export VPSSEC_SSHD_CONFIG="$SANDBOX/etc-ssh/sshd_config"
export UFW_DIR="$SANDBOX/ufw"
export GEO_TMP="$SANDBOX/geotmp"
export VPSSEC_SKIP_ROOT_CHECK=1
export VPSSEC_SKIP_OS_CHECK=1
export PATH="$STUBS:$PATH"
SSH_CFG="$SANDBOX/etc-ssh/sshd_config"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/ufw"
printf '# ufw before rules stub\n*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$SANDBOX/ufw/before.rules"

printf '#Stub sshd_config\nPort 22\n' > "$SSH_CFG"

# ---------- stub: ufw ----------
cat > "$STUBS/ufw" <<'EOF'
#!/usr/bin/env bash
echo "ufw $*" >> "${UFW_LOG:-/tmp/ufw.log}"
case "$1" in
    status) echo "Status: active"; echo "Logging: on";;
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
    *)
        cat <<'TABLE'
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   ESTAB  0      0      192.168.1.5:9999    10.0.0.9:51000
tcp   ESTAB  0      0      192.168.1.5:2222    10.0.0.2:51001
tcp   ESTAB  0      0      192.168.1.5:443     10.0.0.3:51002
udp   ESTAB  0      0      192.168.1.5:9998    10.0.0.9:51003
udp   UNCONN 0      0      127.0.0.53:53       0.0.0.0:*
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
# answers: update=y, ssh-port=2222, close-old=y, ports 443 8443, end,
#          guard-port=18080, open-guard=n, first-scan=n
printf 'y\n2222\ny\n443\n8443\n\n18080\nn\nn\n' \
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
rm -f "$SANDBOX/ufw.log"
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/monitor.sh" --scan > "$SANDBOX/scan.out" 2>&1
if [ -s "$SANDBOX/scan.out" ]; then echo "--- scan.out ---"; cat "$SANDBOX/scan.out"; fi

check "rogue tcp 9999 blocked"          "grep -q 'deny 9999/tcp' '$SANDBOX/ufw.log'"
check "rogue udp 9998 blocked"          "grep -q 'deny 9998/udp' '$SANDBOX/ufw.log'"
check "unconnected udp 53 NOT blocked"  "! grep -q 'deny 53/' '$SANDBOX/ufw.log'"
check "ssh port 2222 NOT blocked"       "! grep -q 'deny 2222/' '$SANDBOX/ufw.log'"
check "allowed port 443 NOT blocked"    "! grep -q 'deny 443/' '$SANDBOX/ufw.log'"
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
echo "=== smoke: help & version ==="
bash "$HERE/vpssec" version | grep -q 'vpssec 1.2.0' && R=0 || R=1
check "version reports 1.2.0"           "[ \"$R\" -eq 0 ]"
bash "$HERE/vpssec" help | grep -q 'update' && R=0 || R=1
check "help mentions update"            "[ \"$R\" -eq 0 ]"

echo
echo "=== smoke: Bot & Scanner Shield ==="
UFW_LOG="$SANDBOX/ufw.log" bash "$HERE/lib/botshield.sh" --enable "" > "$SANDBOX/shield.out" 2>&1 || true
check "shield enabled"                  "grep -q 'Shield enabled' '$SANDBOX/shield.out'"
check "shield conf written"             "grep -q 'SHIELD_ENABLED=1' '$VPSSEC_CONF_DIR/botshield.conf'"
check "shield ufw limit on ssh"         "grep -qE 'limit (2222)/tcp' '$SANDBOX/ufw.log'"
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
check "geo enable writes final DROP"    "grep -q -- '-A ufw-before-input -j DROP' '$UFW_DIR/before.rules'"
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
echo "=== smoke: new menu commands present ==="
printf '10\n0\n0\n' | bash "$HERE/vpssec" > "$SANDBOX/menushield.out" 2>&1 || true
check "menu shows shield entry"         "grep -q 'Bot & Scanner Shield' '$SANDBOX/menushield.out'"
printf '11\n0\n0\n' | bash "$HERE/vpssec" > "$SANDBOX/menugeo.out" 2>&1 || true
check "menu shows geo entry"            "grep -q 'GeoIP Country Filter' '$SANDBOX/menugeo.out'"
bash "$HERE/vpssec" geo list > "$SANDBOX/geocmd.out" 2>&1 || true
check "vpssec geo list works"           "grep -q 'GeoIP country filter' '$SANDBOX/geocmd.out'"
bash "$HERE/vpssec" shield status > "$SANDBOX/shieldcmd.out" 2>&1 || true
check "vpssec shield status works"      "grep -q 'Bot & Scanner Shield' '$SANDBOX/shieldcmd.out'"

echo "==============================================="
echo "SMOKE RESULT: PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed checks:"
    for f in "${FAILURES[@]}"; do echo "  - $f"; done
    exit 1
fi
echo "ALL SMOKE TESTS PASSED"
exit 0
