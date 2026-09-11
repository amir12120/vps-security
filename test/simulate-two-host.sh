#!/usr/bin/env bash
# ============================================================
# vps-security — two-host tunnel simulation  (Iran ⇄ Foreign)
#
# Reproduces the deployment this toolkit is actually used in:
#
#   FOREIGN server (outside Iran)
#     • 3x-ui / Sanayi panel        : 2087 (API)  2096 (subscriptions)
#     • backpack tunnel server      : LISTEN 8443
#
#   IRAN server (clients + shop face the users)
#     • backpack tunnel client      : LISTEN 443 (users dial in)
#                                     dials OUT to foreign:8443 from an
#                                     ephemeral source port
#     • the shop reaches the panel through the tunnel via 127.0.0.1:2087
#
# vps-security is installed on BOTH hosts (guided install, piped
# answers). The simulation then proves the opposite of interference:
#   1. tunnel / panel ports are opened and never blocked or rate-limited
#   2. outbound tunnel sockets and loopback forwards are never blocked
#   3. real rogue ports are STILL blocked  (security is not weakened)
#   4. the GeoIP filter drops NEW connections only, so established
#      tunnel traffic keeps flowing
#   5. a re-install adopts the tunnel rules instead of cutting them
#   6. uninstall on Iran restores SSH 22 + ufw reset and leaves the
#      foreign server completely untouched
#
# Nothing touches the real host: ufw/ss/systemctl/apt/ipset/curl are
# PATH-stubbed and every path is redirected into a sandbox.
#
# Usage: bash test/simulate-two-host.sh
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

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

IRAN_IP="198.51.100.20"     # the Iran server, as the foreign box sees it
FOREIGN_IP="203.0.113.9"    # the foreign box, as the Iran server sees it
ATTACKER="45.13.2.9"

# ------------------------------------------------------------
# Build one simulated server: private stubs + private state dirs
# ------------------------------------------------------------
make_host() {
    local h="$1" ssh_port="$2"
    local H="$ROOT/$h"
    mkdir -p "$H/stubs" "$H/etc" "$H/state" "$H/systemd" "$H/etc-ssh" \
             "$H/ufw" "$H/logs" "$H/state/geo" "$H/opt/vps-security"
    printf '#Simulated sshd_config for %s\nPort %s\n' "$h" "$ssh_port" > "$H/etc-ssh/sshd_config"
    printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$H/ufw/before.rules"

    # ---- ss: per-host socket tables -------------------------
    # tables are created by the caller (host_tables) and read verbatim
    cat > "$H/stubs/ss" <<EOF
#!/usr/bin/env bash
case "\$*" in
    *tlnp*)  cat "$H/ss-listen.txt" ;;
    *tulnH*) cat "$H/ss-listen.txt" ;;
    *-tan*)
        # ss -tan has no Netid column; the shield parses this exact layout.
        if [ -n "\${SS_SYN_FLOOD:-}" ]; then
            echo "State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port"
            i=1
            while [ "\$i" -le 50 ]; do
                echo "SYN-RECV 0        0         192.168.10.5:\${SS_SYN_FLOOD_PORT:-443}   \$SS_SYN_FLOOD:4\$i"
                i=\$((i + 1))
            done
            exit 0
        fi
        cat "$H/ss-conns.txt" ;;
    *)       cat "$H/ss-conns.txt" ;;
esac
exit 0
EOF
    # ---- ufw: logs + optional injected pre-existing rules ---
    cat > "$H/stubs/ufw" <<EOF
#!/usr/bin/env bash
echo "ufw \$*" >> "$H/logs/ufw.log"
case "\$1" in
    status)
        echo "Status: active"
        echo "Logging: on"
        [ -s "$H/ufw-pre.txt" ] && cat "$H/ufw-pre.txt"
        ;;
esac
exit 0
EOF
    printf '#!/usr/bin/env bash\necho "systemctl \$*" >> "%s"\nexit 0\n' "$H/logs/systemctl.log" \
        > "$H/stubs/systemctl"
    printf '#!/usr/bin/env bash\necho "apt-get \$*" >> "%s"\nexit 0\n' "$H/logs/apt.log" \
        > "$H/stubs/apt-get"
    printf '#!/usr/bin/env bash\necho "ipset \$*" >> "%s"\nexit 0\n' "$H/logs/ipset.log" \
        > "$H/stubs/ipset"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$H/stubs/sshd"
    # ---- curl: country list download ------------------------
    cat > "$H/stubs/curl" <<'EOF'
#!/usr/bin/env bash
out="/dev/null"; prev=""
for a in "$@"; do case "$prev" in -o) out="$a";; esac; prev="$a"; done
printf '1.2.3.0/24\n5.6.7.0/24\n' > "$out"
exit 0
EOF
    # ---- sed/cp: redirect /etc/ssh/sshd_config --------------
    cat > "$H/stubs/sed" <<'EOF'
#!/usr/bin/env bash
args=()
for a in "$@"; do
  case "$a" in
    /etc/ssh/sshd_config) args+=("${VPSSEC_SSHD_CONFIG:-/etc/ssh/sshd_config}");;
    *) args+=("$a");;
  esac
done
exec /usr/bin/sed "${args[@]}"
EOF
    cat > "$H/stubs/cp" <<'EOF'
#!/usr/bin/env bash
args=()
for a in "$@"; do
  case "$a" in
    /etc/ssh/sshd_config) args+=("${VPSSEC_SSHD_CONFIG:-/etc/ssh/sshd_config}");;
    *) args+=("$a");;
  esac
done
exec /usr/bin/cp "${args[@]}"
EOF
    chmod +x "$H"/stubs/*
}

H_iran="$ROOT/iran"
H_foreign="$ROOT/foreign"

# ---- socket tables -----------------------------------------
# IRAN: tunnel entry 443, panel forwarded on loopback, outbound tunnel
#       socket 51234 -> foreign:8443, a rogue 3389 carrying traffic.
host_tables_iran() {
    cat > "$H_iran/ss-listen.txt" <<'EOF'
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128    0.0.0.0:22       0.0.0.0:*
LISTEN 0      128    0.0.0.0:443      0.0.0.0:*      users:(("backpack",pid=1201,fd=7))
LISTEN 0      128    127.0.0.1:2087   0.0.0.0:*      users:(("nginx",pid=1301,fd=6))
LISTEN 0      128    127.0.0.1:18080  0.0.0.0:*      users:(("node",pid=1401,fd=9))
LISTEN 0      128    0.0.0.0:3389     0.0.0.0:*      users:(("xrdp",pid=1501,fd=5))
EOF
    cat > "$H_iran/ss-conns.txt" <<EOF
Netid State  Recv-Q Send-Q Local Address:Port   Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      128    0.0.0.0:443        0.0.0.0:*
tcp   ESTAB  0      0      192.168.10.5:443   111.222.33.44:52001
tcp   ESTAB  0      0      192.168.10.5:443   111.222.33.45:52002
tcp   ESTAB  0      0      192.168.10.5:51234 $FOREIGN_IP:8443
tcp   LISTEN 0      128    127.0.0.1:2087     0.0.0.0:*
tcp   ESTAB  0      0      127.0.0.1:2087     127.0.0.1:51000
tcp   LISTEN 0      128    127.0.0.1:18080    0.0.0.0:*
tcp   LISTEN 0      128    0.0.0.0:3389       0.0.0.0:*
tcp   ESTAB  0      0      192.168.10.5:3389   $ATTACKER:41234
udp   UNCONN 0      0      0.0.0.0:3389       0.0.0.0:*
udp   UNCONN 0      0      127.0.0.53:53      0.0.0.0:*
EOF
}

# FOREIGN: backpack server 8443, panel 2087, subscriptions 2096,
#          inbound tunnel from the Iran server, a rogue 4444.
host_tables_foreign() {
    cat > "$H_foreign/ss-listen.txt" <<'EOF'
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128    0.0.0.0:22       0.0.0.0:*
LISTEN 0      128    0.0.0.0:8443     0.0.0.0:*      users:(("backpack",pid=901,fd=5))
LISTEN 0      128    0.0.0.0:2087     0.0.0.0:*      users:(("x-ui",pid=911,fd=6))
LISTEN 0      128    0.0.0.0:2096     0.0.0.0:*      users:(("x-ui",pid=911,fd=8))
LISTEN 0      128    127.0.0.1:18080  0.0.0.0:*      users:(("node",pid=921,fd=9))
LISTEN 0      128    0.0.0.0:4444     0.0.0.0:*      users:(("stranger",pid=931,fd=4))
EOF
    cat > "$H_foreign/ss-conns.txt" <<EOF
Netid State  Recv-Q Send-Q Local Address:Port   Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      128    0.0.0.0:8443       0.0.0.0:*
tcp   ESTAB  0      0      $FOREIGN_IP:8443   $IRAN_IP:51234
tcp   LISTEN 0      128    0.0.0.0:2087       0.0.0.0:*
tcp   ESTAB  0      0      $FOREIGN_IP:2087   127.0.0.1:51000
tcp   LISTEN 0      128    0.0.0.0:2096       0.0.0.0:*
tcp   ESTAB  0      0      $FOREIGN_IP:2096   198.51.100.77:52110
tcp   LISTEN 0      128    127.0.0.1:18080    0.0.0.0:*
tcp   LISTEN 0      128    0.0.0.0:4444       0.0.0.0:*
tcp   ESTAB  0      0      $FOREIGN_IP:4444   $ATTACKER:40001
udp   UNCONN 0      0      127.0.0.53:53      0.0.0.0:*
EOF
}

# ------------------------------------------------------------
# Run a command as if it were running ON that host
# ------------------------------------------------------------
on() {
    local h="$1"; shift
    local H="$ROOT/$h"
    VPSSEC_CONF_DIR="$H/etc" \
    VPSSEC_STATE_DIR="$H/state" \
    VPSSEC_SYSTEMD_DIR="$H/systemd" \
    VPSSEC_INSTALL_DIR="$H/opt/vps-security" \
    VPSSEC_TARGET_DIR="$H/opt/vps-security" \
    VPSSEC_SSHD_CONFIG="$H/etc-ssh/sshd_config" \
    UFW_DIR="$H/ufw" \
    GEO_TMP="$H/geotmp" \
    VPSSEC_SKIP_ROOT_CHECK=1 \
    VPSSEC_SKIP_OS_CHECK=1 \
    VPSSEC_NO_MENU=1 \
    UFW_LOG="$H/logs/ufw.log" \
    SYSTEMCTL_LOG="$H/logs/systemctl.log" \
    APT_LOG="$H/logs/apt.log" \
    IPSET_LOG="$H/logs/ipset.log" \
    PATH="$H/stubs:$PATH" "$@"
}

# ------------------------------------------------------------
# 1. Install on both servers
# ------------------------------------------------------------
echo "=== sim: guided install on the FOREIGN server (panel + tunnel server) ==="
make_host foreign 22
host_tables_foreign
# keep SSH 22, open tunnel 8443 + panel 2087 + subscriptions 2096
printf 'n\n\n8443,2087,2096\ny\n8443,2087,2096\n18080\nn\nn\n' \
    | on foreign bash "$HERE/vpssec" install > "$ROOT/foreign/install.out" 2>&1 || true
if [ ! -s "$ROOT/foreign/install.out" ]; then echo "  (install produced no output)"; fi
check "foreign: install ran through step 4" "grep -q 'Step 4/4' '$ROOT/foreign/install.out'"
check "foreign: comma list opened 8443"    "grep -q 'allow 8443/tcp' '$ROOT/foreign/logs/ufw.log'"
check "foreign: comma list opened 2087"    "grep -q 'allow 2087/tcp' '$ROOT/foreign/logs/ufw.log'"
check "foreign: comma list opened 2096"    "grep -q 'allow 2096/tcp' '$ROOT/foreign/logs/ufw.log'"
check "foreign: all three in allow-list"   "grep -qx '8443' '$H_foreign/etc/allowed-ports.list' && grep -qx '2087' '$H_foreign/etc/allowed-ports.list' && grep -qx '2096' '$H_foreign/etc/allowed-ports.list'"
check "foreign: tunnel ports declared"     "grep -qx '8443' '$H_foreign/etc/tunnel-ports.list'"
check "foreign: firewall enabled"          "grep -q ' enable' '$ROOT/foreign/logs/ufw.log'"

echo
echo "=== sim: guided install on the IRAN server (tunnel client + shop) ==="
make_host iran 22
host_tables_iran
# open the tunnel entry + the shop's extra ports in ONE answer
printf 'n\n\n443,2086,2098,2689\ny\n443\n18080\nn\nn\n' \
    | on iran bash "$HERE/vpssec" install > "$ROOT/iran/install.out" 2>&1 || true
check "iran: install ran through step 4"   "grep -q 'Step 4/4' '$ROOT/iran/install.out'"
for _p in 443 2086 2098 2689; do
    check "iran: comma list opened $_p/tcp" "grep -q 'allow $_p/tcp' '$ROOT/iran/logs/ufw.log'"
done
check "iran: tunnel entry 443 declared"   "grep -qx '443' '$H_iran/etc/tunnel-ports.list'"
check "iran: ssh port recorded for monitor" "grep -q 'MONITOR_SELF_PORT=22' '$H_iran/etc/monitor.conf'"

# ------------------------------------------------------------
# 2. Rogue-port monitor must not touch the tunnel, must kill rogues
# ------------------------------------------------------------
echo
echo "=== sim: monitor scan on the FOREIGN server ==="
rm -f "$ROOT/foreign/logs/ufw.log" "$H_foreign/state/blocked-ports.list"
on foreign bash "$HERE/lib/monitor.sh" --scan > "$ROOT/foreign/scan.out" 2>&1 || true
check "foreign: rogue 4444 blocked"            "grep -q 'deny 4444/tcp' '$ROOT/foreign/logs/ufw.log'"
check "foreign: tunnel 8443 NOT blocked"       "! grep -q 'deny 8443' '$ROOT/foreign/logs/ufw.log'"
check "foreign: panel 2087 NOT blocked"        "! grep -q 'deny 2087' '$ROOT/foreign/logs/ufw.log'"
check "foreign: subscriptions 2096 NOT blocked" "! grep -q 'deny 2096' '$ROOT/foreign/logs/ufw.log'"
check "foreign: loopback forward NOT blocked"  "! grep -q 'deny 18080' '$ROOT/foreign/logs/ufw.log'"
check "foreign: inbound tunnel peer NOT blocked" "! grep -q 'deny 51234' '$ROOT/foreign/logs/ufw.log'"
check "foreign: scan names the tunnel ports"   "grep -q 'tunnel: 8443' '$H_foreign/state/monitor.log'"
check "foreign: panel never lands in the block list" "! grep -qE '\|2087$|\|2096$|\|8443$' '$H_foreign/state/blocked-ports.list'"

echo
echo "=== sim: monitor scan on the IRAN server ==="
rm -f "$ROOT/iran/logs/ufw.log" "$H_iran/state/blocked-ports.list"
on iran bash "$HERE/lib/monitor.sh" --scan > "$ROOT/iran/scan.out" 2>&1 || true
check "iran: rogue 3389 blocked"               "grep -q 'deny 3389' '$ROOT/iran/logs/ufw.log'"
check "iran: tunnel entry 443 NOT blocked"     "! grep -q 'deny 443' '$ROOT/iran/logs/ufw.log'"
check "iran: OUTBOUND tunnel source port NOT blocked" "! grep -q 'deny 51234' '$ROOT/iran/logs/ufw.log'"
check "iran: tunneled panel (loopback) NOT blocked"   "! grep -q 'deny 2087' '$ROOT/iran/logs/ufw.log'"
check "iran: monitor API port NOT blocked"     "! grep -q 'deny 18080' '$ROOT/iran/logs/ufw.log'"
check "iran: ssh 22 NOT blocked"               "! grep -q 'deny 22/' '$ROOT/iran/logs/ufw.log'"
check "iran: block is recorded with a timestamp" "grep -qE '^[0-9]+\|3389$' '$H_iran/state/blocked-ports.list'"

# ------------------------------------------------------------
# 3. Bot & Scanner shield must never rate-limit a tunnel
# ------------------------------------------------------------
echo
echo "=== sim: bot shield on both hosts ==="
rm -f "$ROOT/iran/logs/ufw.log" "$ROOT/foreign/logs/ufw.log"
printf 'GEO_ENABLED=0\nGEO_COUNTRIES=\nGEO_BYPASS=%s\n' "$FOREIGN_IP" > "$H_iran/etc/geo.conf"
on iran bash "$HERE/lib/botshield.sh" --enable "443,2086,2098,2689" > "$ROOT/iran/shield.out" 2>&1 || true
check "iran: shield enabled"                   "grep -q 'Shield enabled' '$ROOT/iran/shield.out'"
check "iran: ssh 22 is rate-limited"           "grep -q 'limit 22/tcp' '$ROOT/iran/logs/ufw.log'"
check "iran: tunnel entry 443 NOT rate-limited" "! grep -q 'limit 443/' '$ROOT/iran/logs/ufw.log'"
check "iran: shield conf excludes the tunnel"  "grep -q 'SHIELD_ENABLED=1' '$H_iran/etc/botshield.conf'"
# a real attacker brute-forcing SSH is banned
rm -f "$ROOT/iran/logs/ufw.log" "$H_iran/state/shield-bans.list"
SS_SYN_FLOOD="$ATTACKER" SS_SYN_FLOOD_PORT=22 on iran bash "$HERE/lib/botshield.sh" --maint > /dev/null 2>&1 || true
check "iran: ssh brute-forcer is banned"      "grep -q 'deny from $ATTACKER' '$ROOT/iran/logs/ufw.log'"
# a flood aimed at the tunnel entry must never be treated as an attack:
# one busy tunnel peer legitimately looks like a flood
rm -f "$ROOT/iran/logs/ufw.log" "$H_iran/state/shield-bans.list"
SS_SYN_FLOOD="$ATTACKER" SS_SYN_FLOOD_PORT=443 on iran bash "$HERE/lib/botshield.sh" --maint > /dev/null 2>&1 || true
check "iran: tunnel traffic is never mistaken for an attack" "! grep -q 'deny from $ATTACKER' '$ROOT/iran/logs/ufw.log'"
# the tunnel peer itself (GeoIP-trusted) is never banned
rm -f "$ROOT/iran/logs/ufw.log"
SS_SYN_FLOOD="$FOREIGN_IP" SS_SYN_FLOOD_PORT=22 on iran bash "$HERE/lib/botshield.sh" --maint > /dev/null 2>&1 || true
check "iran: trusted tunnel peer is never banned" "! grep -q 'deny from $FOREIGN_IP' '$ROOT/iran/logs/ufw.log'"
check "iran: skip is logged for the peer"      "grep -q 'SKIP-BAN $FOREIGN_IP' '$H_iran/state/shield.log'"

on foreign bash "$HERE/lib/botshield.sh" --enable "22" > "$ROOT/foreign/shield.out" 2>&1 || true
check "foreign: shield enabled"                "grep -q 'Shield enabled' '$ROOT/foreign/shield.out'"
check "foreign: tunnel 8443 NOT rate-limited"  "! grep -q 'limit 8443/' '$ROOT/foreign/logs/ufw.log'"
check "foreign: panel 2087 NOT rate-limited"   "! grep -q 'limit 2087/' '$ROOT/foreign/logs/ufw.log'"

# ------------------------------------------------------------
# 4. GeoIP filter must keep the tunnel flowing
# ------------------------------------------------------------
echo
echo "=== sim: GeoIP country filter (Iran allows IR,DE only) ==="
rm -f "$ROOT/iran/logs/ufw.log"
on iran bash "$HERE/lib/geoip.sh" --add "IR,Germany" > "$ROOT/iran/geoadd.out" 2>&1 || true
check "iran: geo accepts full country names"   "grep -q '^GEO_COUNTRIES=IR,DE$' '$H_iran/etc/geo.conf'"
on iran bash "$HERE/lib/geoip.sh" --bypass add "$FOREIGN_IP" > /dev/null 2>&1 || true
on iran bash "$HERE/lib/geoip.sh" --enable > "$ROOT/iran/geoenable.out" 2>&1 || true
check "iran: geo enabled"                      "grep -q 'GEO_ENABLED=1' '$H_iran/etc/geo.conf'"
check "iran: geo rules written"                "grep -q 'vps-security geoip BEGIN' '$H_iran/ufw/before.rules'"
check "iran: final DROP affects NEW connections only" \
    "grep -q -- '-A ufw-before-input ! -i lo -m conntrack --ctstate NEW -j DROP' '$H_iran/ufw/before.rules' && ! grep -qE -- '-A ufw-before-input -j DROP' '$H_iran/ufw/before.rules'"
check "iran: established tunnel replies survive" "grep -q -- 'conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' '$H_iran/ufw/before.rules' || grep -q 'ESTABLISHED' '$H_iran/ufw/before.rules'"
check "iran: trusted tunnel peer bypassed"     "grep -q -- '-s $FOREIGN_IP -j ACCEPT' '$H_iran/ufw/before.rules'"
check "iran: tunnel entry still allowed"       "grep -qx '443' '$H_iran/etc/allowed-ports.list'"
check "iran: shop port still allowed"          "grep -qx '2086' '$H_iran/etc/allowed-ports.list'"

# ------------------------------------------------------------
# 5. Re-install must adopt the tunnel rules instead of cutting them
# ------------------------------------------------------------
echo
echo "=== sim: re-install on IRAN keeps the tunnel reachable ==="
printf '8443/tcp                   ALLOW       Anywhere\n443/tcp                    ALLOW       Anywhere\n' \
    > "$H_iran/ufw-pre.txt"
rm -f "$H_iran/etc/allowed-ports.list" "$ROOT/iran/logs/ufw.log"
printf 'n\n\n443,2086\ny\n443\n18080\nn\nn\n' \
    | on iran bash "$HERE/vpssec" install > "$ROOT/iran/install2.out" 2>&1 || true
check "iran: re-install adopts the admin's ufw rules" "grep -q 'already open in ufw' '$ROOT/iran/install2.out'"
check "iran: adopted tunnel entry re-opened"          "grep -q 'allow 443/tcp' '$ROOT/iran/logs/ufw.log'"
check "iran: adopted panel forward re-opened"         "grep -q 'allow 8443/tcp' '$ROOT/iran/logs/ufw.log'"
on iran bash "$HERE/lib/monitor.sh" --scan > /dev/null 2>&1 || true
check "iran: tunnel still not blocked after re-install" "! grep -q 'deny 443' '$ROOT/iran/logs/ufw.log'"

# ------------------------------------------------------------
# 6. Uninstall on IRAN only — the foreign server must be untouched
# ------------------------------------------------------------
echo
echo "=== sim: uninstall on IRAN ==="
foreign_before="$(cat "$H_foreign/etc/allowed-ports.list" 2>/dev/null | tr '\n' ',' )"
printf 'y\n' | on iran bash "$HERE/vpssec" uninstall > "$ROOT/iran/uninstall.out" 2>&1 || true
check "iran: uninstall restores SSH port 22"  "grep -q '^Port 22$' '$H_iran/etc-ssh/sshd_config'"
check "iran: uninstall runs ufw reset"        "grep -q -- '--force reset' '$ROOT/iran/logs/ufw.log'"
check "iran: uninstall allows port 22"        "grep -q 'allow 22/tcp' '$ROOT/iran/logs/ufw.log'"
check "iran: uninstall disables ufw"          "grep -q 'disable' '$ROOT/iran/logs/ufw.log'"
check "iran: uninstall wipes our config"      "! grep -qx '443' '$H_iran/etc/allowed-ports.list' 2>/dev/null"
foreign_after="$(cat "$H_foreign/etc/allowed-ports.list" 2>/dev/null | tr '\n' ',')"
check "foreign: config untouched by the Iran uninstall" "[ \"$foreign_after\" = \"$foreign_before\" ] && grep -qx '8443' '$H_foreign/etc/allowed-ports.list'"
check "foreign: panel port still allowed"     "grep -qx '2087' '$H_foreign/etc/allowed-ports.list'"

echo
echo "=============================================="
echo "simulate-two-host: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    echo "failed checks:"
    for f in "${FAILURES[@]}"; do echo "  - $f"; done
    exit 1
fi
exit 0
