#!/usr/bin/env bash
# ============================================================
# vps-security — Bot & Scanner Shield
#
# Blocks unauthorized bots and scanners that use the server in
# unusual ways:
#   - Per-IP connection rate limits on the protected ports
#     (ufw "limit": >6 new connections in 30s from one IP -> dropped)
#   - TCP-flag scan drops (NULL / SYN+FIN / SYN+RST / ALL-flags)
#   - Auto-ban: an IP that crosses the rate threshold is banned
#     (ufw deny from IP) for BAN_SECONDS (default 1 hour)
#
# All rules are written through ufw so they survive reboots.
#
# Usage:
#   botshield.sh --enable [ports csv]   install rules
#   botshield.sh --disable              remove all shield rules
#   botshield.sh --status               shield state + banned IPs
#   botshield.sh --list                 list banned IPs
#   botshield.sh --unban <ip>           release a banned IP now
#   botshield.sh --maint                ban-expiry maintenance (timer)
#   botshield.sh --health               exit 0 if shield enabled
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

SHIELD_CONF="$VPSSEC_CONF_DIR/botshield.conf"
BANS_FILE="$VPSSEC_STATE_DIR/shield-bans.list"
BAN_LOG="$VPSSEC_STATE_DIR/shield-bans.log"
SHIELD_LOG="$VPSSEC_STATE_DIR/shield.log"
BAN_SECONDS="${BAN_SECONDS:-3600}"
BAN_THRESHOLD="${BAN_THRESHOLD:-40}"   # bans logged when hits exceed this

cmd_ufw()       { ufw "$@"; }
cmd_systemctl() { systemctl "$@"; }
have_iptables() { command -v iptables >/dev/null 2>&1; }

# ---------- conf ----------

shield_is_enabled() { [ -f "$SHIELD_CONF" ] && grep -q '^SHIELD_ENABLED=1$' "$SHIELD_CONF" 2>/dev/null; }

load_shield_conf() {
    SHIELD_PORTS="${SHIELD_PORTS:-}"
    [ -f "$SHIELD_CONF" ] && . "$SHIELD_CONF" 2>/dev/null
    return 0
}

save_shield_conf() {
    ensure_dirs
    cat > "$SHIELD_CONF" <<EOF
SHIELD_ENABLED=${SHIELD_ENABLED:-0}
SHIELD_PORTS=${SHIELD_PORTS:-}
EOF
    chmod 600 "$SHIELD_CONF"
}

# Protected ports: explicit list, else the allow-list minus SSH port
# (SSH is handled separately below with its own limit).
#
# TUNNEL PORTS ARE EXCLUDED: `ufw limit` drops a source after ~6 new
# connections in 30s, and a busy tunnel means one peer IP opening exactly
# that kind of burst — rate-limiting it would cut the tunnel for the
# admin's own customers.
shield_ports() {
    local ports="$1"
    local sp p out=""
    sp="$(grep -E '^\s*Port\s+' "${VPSSEC_SSHD_CONFIG:-/etc/ssh/sshd_config}" 2>/dev/null | tail -1 | awk '{print $2}')"
    [ -z "$sp" ] && sp="22"
    if [ -z "$ports" ]; then
        load_allowed_ports
        for p in "${ALLOWED_PORTS[@]:-}"; do
            [ -z "$p" ] && continue
            [ "$p" = "$sp" ] && continue
            port_is_tunnel "$p" && continue
            out+="${out:+,}$p"
        done
    else
        IFS=',' read -ra want <<< "$ports"
        for p in "${want[@]:-}"; do
            [ -z "$p" ] && continue
            [ "$p" = "$sp" ] && continue
            port_is_tunnel "$p" && continue
            out+="${out:+,}$p"
        done
    fi
    printf '%s' "$out"
}

# Is this IP already declared trusted (GeoIP bypass list)?
ip_is_trusted() {
    local ip
    while IFS= read -r ip; do
        [ "$ip" = "$1" ] && return 0
    done < <(trusted_ip_list)
    return 1
}

# ---------- before.rules TCP-flag drop block ----------

BEFORE_RULES="$UFW_DIR/before.rules"
MARK_BEGIN="# --- vps-security botshield BEGIN ---"
MARK_END="# --- vps-security botshield END ---"

flag_block_text() {
    cat <<EOF
$MARK_BEGIN
# drop TCP-flag scans/attacks (NULL, SYN+FIN, SYN+RST, ALL flags)
-A ufw-before-input -p tcp --tcp-flags ALL NONE -j DROP
-A ufw-before-input -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
-A ufw-before-input -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
-A ufw-before-input -p tcp --tcp-flags ALL ALL -j DROP
$MARK_END
EOF
}

write_flag_drops() {
    [ -f "$BEFORE_RULES" ] || return 0
    # strip any previous block, then append fresh
    sed -i "/^${MARK_BEGIN}\$/,/^${MARK_END}\$/d" "$BEFORE_RULES"
    printf '\n%s\n' "$(flag_block_text)" >> "$BEFORE_RULES"
    return 0
}

remove_flag_drops() {
    [ -f "$BEFORE_RULES" ] || return 0
    sed -i "/^${MARK_BEGIN}\$/,/^${MARK_END}\$/d" "$BEFORE_RULES"
    return 0
}

# ---------- rate limits ----------

apply_limit_rules() {
    local ports_csv="$1" ssh_port="$2" p
    # SSH always gets a limit (brute-force protection)
    [ -n "$ssh_port" ] && cmd_ufw limit "$ssh_port"/tcp >/dev/null 2>&1
    IFS=',' read -ra plist <<< "$ports_csv"
    for p in "${plist[@]:-}"; do
        [ -z "$p" ] && continue
        port_is_tunnel "$p" && continue
        cmd_ufw limit "$p"/tcp >/dev/null 2>&1
        cmd_ufw limit "$p"/udp >/dev/null 2>&1
    done
    return 0
}

remove_limit_rules() {
    local ports_csv="$1" ssh_port="$2" p
    [ -n "$ssh_port" ] && cmd_ufw delete limit "$ssh_port"/tcp >/dev/null 2>&1
    IFS=',' read -ra plist <<< "$ports_csv"
    for p in "${plist[@]:-}"; do
        [ -z "$p" ] && continue
        port_is_tunnel "$p" && continue
        cmd_ufw delete limit "$p"/tcp >/dev/null 2>&1
        cmd_ufw delete limit "$p"/udp >/dev/null 2>&1
    done
    return 0
}

# ---------- bans ----------

bans_count() {
    [ -f "$BANS_FILE" ] && grep -cE '^[0-9]+\|' "$BANS_FILE" || true
}

ban_ip() {
    local ip="$1" hits="$2"
    ensure_dirs
    grep -qF "|$ip" "$BANS_FILE" 2>/dev/null && return 0
    # SAFETY on tunnelled servers: never ban the machine's own addresses
    # (that is the tunnel talking to itself) or a peer the admin declared
    # trusted — banning either one takes the tunnel down.
    if ip_is_local "$ip" || ip_is_trusted "$ip"; then
        printf '%s SKIP-BAN %s (local/trusted peer)\n' \
            "$(date '+%Y-%m-%d %H:%M:%S')" "$ip" >> "$SHIELD_LOG"
        return 0
    fi
    cmd_ufw deny from "$ip" >/dev/null 2>&1 || true
    printf '%s|%s\n' "$(date +%s)" "$ip" >> "$BANS_FILE"
    printf '%s BAN %s (hits=%s, expires in %ss)\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$ip" "$hits" "$BAN_SECONDS" >> "$BAN_LOG"
}

unban_ip() {
    local ip="$1"
    cmd_ufw delete deny from "$ip" >/dev/null 2>&1 || true
    [ -f "$BANS_FILE" ] && sed -i "/|$ip\$/d" "$BANS_FILE"
    printf '%s UNBAN %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$ip" >> "$BAN_LOG"
}

unban_expired() {
    [ -f "$BANS_FILE" ] || return 0
    local now ts ip removed=0
    now="$(date +%s)"
    while IFS='|' read -r ts ip || [ -n "${ts:-}" ]; do
        [ -z "${ts:-}" ] && continue
        if [ $((now - ts)) -ge "$BAN_SECONDS" ]; then
            unban_ip "$ip"
            removed=$((removed + 1))
        fi
    done < "$BANS_FILE"
    [ "$removed" -gt 0 ] && printf '%s expired bans removed: %d\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$removed" >> "$SHIELD_LOG"
    return 0
}

# Count hit records for an IP (records written by the watcher)
ip_hits() {
    [ -f "$VPSSEC_STATE_DIR/shield-hits.log" ] && grep -cF "|$ip" "$VPSSEC_STATE_DIR/shield-hits.log" 2>/dev/null || echo 0
}

# Print "<local> <peer>" for every half-open (SYN-RECV) connection.
#
# NOTE: `ss -tan` prints no Netid column while `ss -tunap` does, so the
# column positions differ. This used to read $1/$2 as "tcp"/"SYN-RECV"
# (the -tunap layout) while reading $4/$5 as local/peer (the -tan layout),
# which meant the auto-ban never matched a single connection. Both layouts
# are accepted here.
ss_syn_recv() {
    ss -tan 2>/dev/null | awk '
        NR == 1 && ($1 == "State" || $1 == "Netid") { next }
        {
            if ($1 == "tcp" || $1 == "tcp6" || $1 == "udp" || $1 == "udp6") {
                st = $2; l = $5; r = $6
            } else {
                st = $1; l = $4; r = $5
            }
            if (st == "SYN-RECV") print l " " r
        }'
}

# Inspect recent connections (ss) and ban IPs with too many NEW
# connections to protected ports.
scan_and_ban() {
    command -v ss >/dev/null 2>&1 || return 0
    # zombie guard: never scan/ban while the shield is disabled
    shield_is_enabled || return 0
    load_shield_conf
    load_tunnel_ports
    local ports_csv
    ports_csv="$(shield_ports "$SHIELD_PORTS")"
    [ -z "$ports_csv" ] && return 0

    local pairs
    pairs="$(ss_syn_recv)"
    [ -z "$pairs" ] && return 0

    local syn_ports sp_port ip
    syn_ports="$(printf '%s\n' "$pairs" | awk '{print $1}' \
        | sed -E 's/.*[:.]([0-9]+)$/\1/' | sort -u || true)"
    [ -z "$syn_ports" ] && return 0

    for sp_port in $syn_ports; do
        case ",$ports_csv," in
            *",$sp_port,"*) ;;
            *) continue ;;
        esac
        # offending peer IPs on that port (ban_ip itself refuses
        # loopback/private/trusted peers)
        for ip in $(printf '%s\n' "$pairs" \
            | awk -v P=":$sp_port" '$1 ~ P {print $2}' \
            | sed -E 's/^\[?([0-9a-fA-F:.]+)\]?:[0-9]+$/\1/' | sort | uniq -c \
            | awk -v T="$BAN_THRESHOLD" '$1 >= T {print $2}'); do
            ban_ip "$ip" "$(printf '%s\n' "$pairs" \
                | awk -v P=":$sp_port" -v IP="$ip" '$1 ~ P && $2 ~ IP' | wc -l)"
        done
    done
    return 0
}

# ---------- actions ----------

shield_enable() {
    load_shield_conf
    ensure_dirs
    load_tunnel_ports
    local ports_csv="${1:-}"
    SHIELD_PORTS="$(shield_ports "$ports_csv")"
    SHIELD_ENABLED=1
    save_shield_conf

    local sp
    sp="$(grep -E '^\s*Port\s+' "${VPSSEC_SSHD_CONFIG:-/etc/ssh/sshd_config}" 2>/dev/null | tail -1 | awk '{print $2}')"
    [ -z "$sp" ] && sp="22"

    apply_limit_rules "$SHIELD_PORTS" "$sp"
    write_flag_drops
    if have_iptables && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -qx 'Status: active'; then
        ufw reload >/dev/null 2>&1 || true
    fi

    # maintenance timer
    cat > "$VPSSEC_SYSTEMD_DIR/vps-security-shield.service" <<EOF
[Unit]
Description=vps-security botshield ban maintenance

[Service]
Type=oneshot
ExecStart=$SCRIPT_DIR/lib/botshield.sh --maint
EOF
    cat > "$VPSSEC_SYSTEMD_DIR/vps-security-shield.timer" <<EOF
[Unit]
Description=Run botshield ban maintenance every 10 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=10min
Unit=vps-security-shield.service

[Install]
WantedBy=timers.target
EOF
    cmd_systemctl daemon-reload
    cmd_systemctl enable --now vps-security-shield.timer

    printf '%s shield enabled (ports: %s, ssh: %s)\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${SHIELD_PORTS:-(none)}" "$sp" >> "$SHIELD_LOG"
    ok "Bot & Scanner Shield enabled."
    ok "  rate limit  : ufw limit on SSH and protected ports (>6 new conns/30s dropped)"
    ok "  scan drops  : NULL / SYN+FIN / SYN+RST / ALL-flag packets dropped"
    ok "  auto-ban    : SYN-flood IPs banned for $((BAN_SECONDS / 60)) minutes"
    ok "  maintenance : timer every 10 min (ban expiry)"
}

shield_disable() {
    load_shield_conf
    local sp
    sp="$(grep -E '^\s*Port\s+' "${VPSSEC_SSHD_CONFIG:-/etc/ssh/sshd_config}" 2>/dev/null | tail -1 | awk '{print $2}')"
    [ -z "$sp" ] && sp="22"
    # SAFETY: release ALL active bans first — the maintenance timer that
    # expires bans is being removed, so without this every banned IP
    # would stay banned forever with no expiry mechanism.
    if [ -f "$BANS_FILE" ]; then
        local ts ip
        while IFS='|' read -r ts ip || [ -n "${ts:-}" ]; do
            [ -z "${ts:-}" ] && continue
            unban_ip "$ip"
        done < "$BANS_FILE"
    fi
    remove_limit_rules "$SHIELD_PORTS" "$sp"
    remove_flag_drops
    if have_iptables && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -qx 'Status: active'; then
        ufw reload >/dev/null 2>&1 || true
    fi
    cmd_systemctl disable --now vps-security-shield.timer 2>/dev/null || true
    rm -f "$VPSSEC_SYSTEMD_DIR"/vps-security-shield.{service,timer}
    cmd_systemctl daemon-reload
    SHIELD_ENABLED=0
    save_shield_conf
    printf '%s shield disabled\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$SHIELD_LOG"
    ok "Bot & Scanner Shield disabled — all shield rules removed."
}

shield_status() {
    ensure_dirs
    load_shield_conf
    echo "=== Bot & Scanner Shield ==="
    if shield_is_enabled; then
        echo "State        : ENABLED"
    else
        echo "State        : disabled"
    fi
    echo "Protected ports: ${SHIELD_PORTS:-(auto: allow-list minus SSH)}"
    echo "Ban duration : ${BAN_SECONDS}s"
    echo "Banned IPs   : $(bans_count)"
    if [ -f "$BANS_FILE" ] && [ -s "$BANS_FILE" ]; then
        local now ts ip remain
        now="$(date +%s)"
        while IFS='|' read -r ts ip || [ -n "${ts:-}" ]; do
            [ -z "${ts:-}" ] && continue
            remain=$((BAN_SECONDS - (now - ts)))
            [ "$remain" -lt 0 ] && remain=0
            printf '  - %s (unbans in %dm%02ds)\n' "$ip" $((remain / 60)) $((remain % 60))
        done < "$BANS_FILE"
    fi
    [ -f "$BAN_LOG" ] && { echo "Recent events:"; tail -n 8 "$BAN_LOG" | sed 's/^/  /'; }
    return 0
}

case "${1:-}" in
    --enable)  shift; need_root; shield_enable "${1:-}" ;;
    --disable) need_root; shield_disable ;;
    --status)  shield_status ;;
    --list)    [ -f "$BANS_FILE" ] && cat "$BANS_FILE" || true ;;
    --unban)
        shift
        IP="$1"
        printf '%s' "$IP" | grep -qE '^[0-9a-fA-F.:]+$' || die "invalid IP"
        need_root
        unban_ip "$IP"
        ok "IP $IP unbanned."
        ;;
    --maint)   need_root; unban_expired; scan_and_ban ;;
    --health)  shield_is_enabled ;;
    *) die "usage: botshield.sh (--enable [ports]|--disable|--status|--list|--unban <ip>|--maint|--health)" ;;
esac
