#!/usr/bin/env bash
# ============================================================
# vps-security — Bot & Scanner Shield (fail2ban-style)
#
# The old design used `ufw limit`, which drops a source after ~6 NEW
# connections in 30s. That is exactly what a busy tunnel looks like —
# one peer IP opening a burst of connections — so enabling the shield
# cut the admin's own VPN. It also rate-limited whole ports, so one
# noisy customer could break the service for everyone.
#
# The new design is a classic fail2ban per-IP counter:
#   - NO per-port rate limits at all — legitimate clients can never be
#     crowded out by other users of the same port
#   - the shield watches connections (via `ss`) and counts them PER IP
#   - an IP that crosses SHIELD_THRESHOLD new connections to a
#     PROTECTED port within the SHIELD_WINDOW is reported (approve mode)
#     or banned (auto mode) — for BAN_SECONDS, releasable any time
#   - tunnel ports, trusted tunnel peers (GeoIP bypass), local/private
#     addresses and the admin's own SSH client are always exempt
#   - TCP-flag scan drops stay as they are (harmless to tunnels)
#
# Usage:
#   botshield.sh --enable [ports csv]   arm the shield
#   botshield.sh --disable              remove all shield state
#   botshield.sh --status               shield state + banned IPs
#   botshield.sh --list                 list banned IPs
#   botshield.sh --unban <ip>           release a banned IP now
#   botshield.sh --ban-now <ip> [note]  ban an IP (used after an approval)
#   botshield.sh --maint                counter/ban maintenance (timer)
#   botshield.sh --health               exit 0 if shield enabled
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

SHIELD_CONF="$VPSSEC_CONF_DIR/botshield.conf"
BANS_FILE="$VPSSEC_STATE_DIR/shield-bans.list"
BAN_LOG="$VPSSEC_STATE_DIR/shield-bans.log"
SHIELD_LOG="$VPSSEC_STATE_DIR/shield.log"
BAN_SECONDS="${BAN_SECONDS:-86400}"    # 24 hours default
SHIELD_THRESHOLD="${SHIELD_THRESHOLD:-40}"  # new conns from ONE IP to trigger
SHIELD_WINDOW="${SHIELD_WINDOW:-30}"   # seconds a hit stays in the counter
SHIELD_MODE="${SHIELD_MODE:-approve}"  # approve | auto

have_iptables() { command -v iptables >/dev/null 2>&1; }

# ---------- conf ----------

shield_is_enabled() { [ -f "$SHIELD_CONF" ] && grep -q '^SHIELD_ENABLED=1$' "$SHIELD_CONF" 2>/dev/null; }

load_shield_conf() {
    SHIELD_PORTS="${SHIELD_PORTS:-}"
    # shellcheck disable=SC1090
    [ -f "$SHIELD_CONF" ] && . "$SHIELD_CONF" 2>/dev/null
    return 0
}

save_shield_conf() {
    ensure_dirs
    cat > "$SHIELD_CONF" <<EOF
SHIELD_ENABLED=${SHIELD_ENABLED:-0}
SHIELD_PORTS=${SHIELD_PORTS:-}
SHIELD_MODE=${SHIELD_MODE:-approve}
BAN_SECONDS=${BAN_SECONDS:-86400}
SHIELD_THRESHOLD=${SHIELD_THRESHOLD:-40}
SHIELD_WINDOW=${SHIELD_WINDOW:-30}
EOF
    chmod 600 "$SHIELD_CONF"
}

# Protected ports: explicit list, else the allow-list.
#
# TUNNEL PORTS ARE EXCLUDED: `ufw limit` drops a source after ~6 new
# connections in 30s, and a busy tunnel means one peer IP opening exactly
# that kind of burst — rate-limiting it would cut the tunnel for the
# admin's own customers.
#
# The SSH PORT IS ALWAYS INCLUDED: brute-force floods aimed at SSH are the
# most common bot traffic there is, so it must be bannable (it only gets a
# `ufw limit` when the port is not in this list). It can never be a tunnel
# port in practice, but if an admin declared it as one it is skipped too.
shield_ports() {
    local ports="$1"
    local sp p out=""
    sp="$(grep -E '^\s*Port\s+' "${VPSSEC_SSHD_CONFIG:-/etc/ssh/sshd_config}" 2>/dev/null | tail -1 | awk '{print $2}')"
    [ -z "$sp" ] && sp="22"
    if [ -z "$ports" ]; then
        load_allowed_ports
        for p in "${ALLOWED_PORTS[@]:-}"; do
            [ -z "$p" ] && continue
            port_is_tunnel "$p" && continue
            out+="${out:+,}$p"
        done
    else
        IFS=',' read -ra want <<< "$ports"
        for p in "${want[@]:-}"; do
            [ -z "$p" ] && continue
            port_is_tunnel "$p" && continue
            out+="${out:+,}$p"
        done
    fi
    if ! port_is_tunnel "$sp"; then
        case ",$out," in
            *",$sp,"*) ;;
            *) out+="${out:+,}$sp" ;;
        esac
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
# None. `ufw limit` was removed on purpose: it counts NEW connections per
# (port, source) pair and drops the source after ~6 in 30s — a busy tunnel
# or one active VPN customer hits that instantly. Detection is per-IP and
# threshold-based instead (scan_and_ban below).

# ---------- per-IP hit counters (the fail2ban part) ----------

HITS_FILE="$VPSSEC_STATE_DIR/shield-hits.list"

# Record one new connection: <unix-ts>|<ip>|<port>. Old entries are
# pruned against SHIELD_WINDOW so the counter reflects "recent" activity.
record_hit() {
    local ip="$1" port="$2" now cutoff
    now="$(date +%s)"
    cutoff=$((now - SHIELD_WINDOW))
    {
        # keep only recent lines
        while IFS='|' read -r ts h_ip h_port || [ -n "${ts:-}" ]; do
            [ -z "${ts:-}" ] && continue
            [ "$ts" -ge "$cutoff" ] 2>/dev/null && \
                printf '%s|%s|%s\n' "$ts" "$h_ip" "$h_port"
        done < "$HITS_FILE" 2>/dev/null || true
        printf '%s|%s|%s\n' "$now" "$ip" "$port"
    } > "$HITS_FILE.tmp" 2>/dev/null || : > "$HITS_FILE.tmp"
    mv "$HITS_FILE.tmp" "$HITS_FILE"
}

# How many recent hits an IP has on a given port.
hits_count() {
    local ip="$1" port="$2" now cutoff
    now="$(date +%s)"
    cutoff=$((now - SHIELD_WINDOW))
    awk -F'|' -v ip="$ip" -v port="$port" -v cutoff="$cutoff" \
        '$1 >= cutoff && $2 == ip && $3 == port { n++ } END { print n + 0 }' \
        "$HITS_FILE" 2>/dev/null
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
    local now ts ip removed=0 keep tmp
    now="$(date +%s)"
    # Decide first, rewrite once: unban_ip mutates the very file this loop
    # reads (same hazard ShellCheck flagged in the port monitor).
    tmp="$(mktemp)"
    while IFS='|' read -r ts ip || [ -n "${ts:-}" ]; do
        [ -z "${ts:-}" ] && continue
        if [ $((now - ts)) -ge "$BAN_SECONDS" ]; then
            unban_ip "$ip"
            removed=$((removed + 1))
        else
            printf '%s|%s\n' "$ts" "$ip" >> "$tmp"
        fi
    done < "$BANS_FILE"
    if [ "$removed" -gt 0 ]; then
        keep="$tmp"
        mv "$keep" "$BANS_FILE"
        printf '%s expired bans removed: %d\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$removed" >> "$SHIELD_LOG"
    else
        rm -f "$tmp"
    fi
    return 0
}

# Count hit records for an IP (records written by the watcher)
ip_hits() {
    [ -f "$VPSSEC_STATE_DIR/shield-hits.log" ] && grep -cF "|$ip" "$VPSSEC_STATE_DIR/shield-hits.log" 2>/dev/null || echo 0
}

# Print "<local> <peer>" for every NEW inbound TCP connection.
#
# NOTE: `ss -tan` prints no Netid column while `ss -tunap` does, so the
# column positions differ. Both layouts are accepted here.
ss_new_conns() {
    ss -tan 2>/dev/null | awk '
        NR == 1 && ($1 == "State" || $1 == "Netid") { next }
        {
            if ($1 == "tcp" || $1 == "tcp6" || $1 == "udp" || $1 == "udp6") {
                st = $2; l = $5; r = $6
            } else {
                st = $1; l = $4; r = $5
            }
            if (st == "SYN-RECV" || st == "SYN-SENT" || st == "ESTAB") print l " " r
        }'
}

# Count hits per peer IP and act when one crosses the threshold.
# Only PROTECTED ports are counted; the caller has already excluded
# tunnel ports from that list, and ban_ip refuses local/trusted peers.
scan_and_ban() {
    command -v ss >/dev/null 2>&1 || return 0
    # zombie guard: never scan/ban while the shield is disabled
    shield_is_enabled || return 0
    load_shield_conf
    load_tunnel_ports
    local ports_csv
    ports_csv="$(shield_ports "$SHIELD_PORTS")"
    [ -z "$ports_csv" ] && return 0

    # 1. feed the counters with the connections we see right now
    local pairs l_port ip
    pairs="$(ss_new_conns)"
    [ -n "$pairs" ] && while read -r l r; do
        [ -z "${l:-}" ] && continue
        l_port="$(printf '%s' "$l" | sed -E 's/.*[:.]([0-9]+)$/\1/')"
        case ",$ports_csv," in *",$l_port,"*) ;; *) continue ;; esac
        ip="$(printf '%s' "$r" | sed -E 's/^\[?([0-9a-fA-F:.]+)\]?:[0-9]+$/\1/')"
        [ -n "$ip" ] && record_hit "$ip" "$l_port"
    done <<< "$pairs"

    # 2. any protected port where SOMEONE is connecting right now?
    [ -n "$pairs" ] || pairs="$(ss_syn_recv)"
    local act_ports
    act_ports="$(printf '%s\n' "$pairs" | awk '{print $1}' \
        | sed -E 's/.*[:.]([0-9]+)$/\1/' | sort -u \
        | while IFS= read -r p; do
            case ",$ports_csv," in *",$p,"*) echo "$p" ;; esac
          done)"
    [ -z "$act_ports" ] && return 0

    # 3. per-IP counters on those ports (from the hits file, not from the
    #    instantaneous socket table — that is what makes this fail2ban
    #    rather than a single-snapshot guess)
    local sp_port hit_ip hits
    for sp_port in $act_ports; do
        while read -r hit_ip; do
            [ -z "$hit_ip" ] && continue
            hits="$(hits_count "$hit_ip" "$sp_port")"
            [ "$hits" -ge "$SHIELD_THRESHOLD" ] || continue
            if [ "$SHIELD_MODE" = "auto" ]; then
                ban_ip "$hit_ip" "$hits"
            else
                # Approval mode: report the IP and let the admin decide.
                # A monitor, a backup host or a tunnel peer can look exactly
                # like a flood, and an autonomous ban of one of those is very
                # hard to notice from the outside.
                printf '%s DETECT %s (hits=%s on port %s — awaiting approval)\n' \
                    "$(date '+%Y-%m-%d %H:%M:%S')" "$hit_ip" "$hits" "$sp_port" >> "$SHIELD_LOG"
                bash "$SCRIPT_DIR/lib/alerts.sh" --report ip "$hit_ip" "$sp_port" \
                    "$hits connections to port $sp_port within ${SHIELD_WINDOW}s" || true
            fi
        done < <(awk -F'|' -v P="$sp_port" '{ print $2 }' "$HITS_FILE" 2>/dev/null \
            | sort -u)
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
    ok "  detection   : per-IP — more than $SHIELD_THRESHOLD connections to a"
    ok "                protected port within ${SHIELD_WINDOW}s is an attack"
    ok "  scan drops  : NULL / SYN+FIN / SYN+RST / ALL-flag packets dropped"
    ok "  tunnels     : declared tunnel ports and trusted peers are exempt"
    ok "  no ufw limit: legitimate clients are never rate-limited"
    if [ "$SHIELD_MODE" = "auto" ]; then
        ok "  auto-ban    : flooding IPs banned for $((BAN_SECONDS / 3600))h without asking"
    else
        ok "  approve     : flooding IPs are reported; you decide (vpssec alerts)"
        ok "  ban window  : $((BAN_SECONDS / 3600))h once you approve"
    fi
    ok "  maintenance : timer every 10 min (ban expiry)"
}

shield_disable() {
    load_shield_conf
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
    rm -f "$HITS_FILE" "$HITS_FILE.tmp"
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
    if [ "$SHIELD_MODE" = "auto" ]; then
        echo "Mode         : auto (ban immediately)"
    else
        echo "Mode         : approve (ask the admin before banning)"
    fi
    echo "Trigger      : >$SHIELD_THRESHOLD conns / ${SHIELD_WINDOW}s from one IP"
    echo "Ban duration : ${BAN_SECONDS}s"
    echo "Banned IPs   : $(bans_count)"
    echo "Awaiting your approval: $(bash "$SCRIPT_DIR/lib/alerts.sh" --count 2>/dev/null || echo 0)"
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
    --ban-now)
        shift
        IP="${1:-}"
        printf '%s' "$IP" | grep -qE '^[0-9a-fA-F.:]+$' || die "invalid IP"
        need_root
        # The admin-configured ban window is the authority; an env override
        # (approval path) still wins so approve/report stay consistent.
        load_shield_conf
        ban_ip "$IP" "${2:-approved by admin}"
        # Never claim a ban that was refused (local/private or trusted peer):
        # the approval path must report failure so the alert stays queued.
        if [ -f "$BANS_FILE" ] && grep -qF "|$IP" "$BANS_FILE" 2>/dev/null; then
            ok "IP $IP banned for $((BAN_SECONDS / 3600))h."
        else
            warn "IP $IP was NOT banned (local/private or trusted peer) — nothing was applied."
            exit 1
        fi
        ;;
    --maint)   need_root; load_shield_conf; unban_expired; scan_and_ban ;;
    --health)  shield_is_enabled ;;
    *) die "usage: botshield.sh (--enable [ports]|--disable|--status|--list|--unban <ip>|--ban-now <ip>|--maint|--health)" ;;
esac
