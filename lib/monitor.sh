#!/usr/bin/env bash
# ============================================================
# vps-security — rogue-port monitor
#
# Every run (systemd timer fires every 30 minutes):
#   1. Unblock any ports whose 1-hour block has expired.
#   2. Scan live TCP/UDP connections (ss -tunap).
#   3. Any LOCAL port that is actively transferring data (has at
#      least one established/active connection) and is NOT in the
#      user-approved allow-list gets BLOCKED via ufw for one hour.
#   4. Approved ports, the monitor's own connections, and already
#      blocked ports are skipped.
#
# blocked-ports.list lines have the form:  <unix-ts>|<port>
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

MONITOR_LOG="$VPSSEC_STATE_DIR/monitor.log"
BLOCK_SECONDS="${BLOCK_SECONDS:-3600}"          # 1 hour default

have_ss()  { command -v ss >/dev/null 2>&1; }
have_ufw() { command -v ufw >/dev/null 2>&1; }
ss_raw()   { ss -tunap 2>/dev/null || true; }

# Extract the local ports of all ACTIVE connections (established TCP
# or connected UDP sockets).
# ss -tunap fields: $1=netid $2=state $3=recvq $4=sendq $5=local $6=peer
active_local_ports() {
    have_ss || return 0
    ss_raw | awk '
        NR > 1 {
            if ($1 == "tcp" && $2 != "LISTEN") print $5;
            else if ($1 == "udp" && $2 == "ESTAB") print $5;
        }
    ' \
    | sed -E 's/^\[?([0-9a-fA-F:.]+)?\]?[:.]([0-9]+)$/\2/' \
    | grep -E '^[0-9]+$' || true
}

# Remove expired blocks (older than BLOCK_SECONDS)
unblock_expired() {
    [ -f "$BLOCK_LIST_FILE" ] || return 0
    local now ts port removed=0
    now="$(date +%s)"
    while IFS='|' read -r ts port || [ -n "$ts" ]; do
        [ -z "${ts:-}" ] && continue
        port="${port:-}"
        if is_valid_port "$port" && [ $((now - ts)) -ge "$BLOCK_SECONDS" ]; then
            if have_ufw; then
                ufw delete deny "$port"/tcp >/dev/null 2>&1 || true
                ufw delete deny "$port"/udp >/dev/null 2>&1 || true
            fi
            sed -i "/|${port}\$/d" "$BLOCK_LIST_FILE" 2>/dev/null || true
            log_action "UNBLOCK" "$port" "1h block expired"
            removed=$((removed + 1))
        fi
    done < "$BLOCK_LIST_FILE"
    [ "$removed" -gt 0 ] && printf '%s unblocked %d expired port(s)\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$removed" >> "$MONITOR_LOG"
    return 0
}

# Block a rogue port for BLOCK_SECONDS
block_port() {
    local port="$1" reason="$2" self_port="" guard_port=""
    ensure_dirs

    # Never block our own control ports (ssh port, guard API port)
    [ -f "$MONITOR_CONF" ] && . "$MONITOR_CONF" 2>/dev/null
    self_port="${MONITOR_SELF_PORT:-}"
    guard_port="${MONITOR_GUARD_PORT:-}"
    # Defense in depth: always protect the CURRENT sshd port too, even
    # when monitor.conf is missing (e.g. after an empty-ports install)
    # so a manual scan can never lock the administrator out.
    if [ -z "$self_port" ]; then
        self_port="$(grep -E '^\s*Port\s+' "${VPSSEC_SSHD_CONFIG:-/etc/ssh/sshd_config}" 2>/dev/null | tail -1 | awk '{print $2}')"
    fi
    if [ "$port" = "$self_port" ] || [ "$port" = "$guard_port" ]; then
        printf '%s SKIP %s (own control port)\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$port" >> "$MONITOR_LOG"
        return 0
    fi

    if have_ufw; then
        ufw deny "$port"/tcp >/dev/null 2>&1 || true
        ufw deny "$port"/udp >/dev/null 2>&1 || true
    else
        printf '%s WARN ufw missing; cannot firewall-block %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$port" >> "$MONITOR_LOG"
    fi

    printf '%s|%s\n' "$(date +%s)" "$port" >> "$BLOCK_LIST_FILE"
    log_action "BLOCK" "$port" "$reason"
    printf '%s BLOCK %s (%s) — blocked for %s seconds\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$port" "$reason" "$BLOCK_SECONDS" >> "$MONITOR_LOG"
}

# Main scan
run_scan() {
    ensure_dirs
    load_allowed_ports

    printf '%s scan start (allowed: %s)\n' "$(date '+%Y-%m-%d %H:%M:%S')" \
        "${ALLOWED_PORTS[*]:-none}" >> "$MONITOR_LOG"

    unblock_expired

    local ports found=0 blocked=0
    ports="$(active_local_ports)"
    [ -z "$ports" ] && return 0

    while IFS= read -r port; do
        [ -z "$port" ] && continue
        found=$((found + 1))
        port_is_allowed "$port" && continue
        port_is_blocked "$port" && continue
        block_port "$port" "rogue traffic detected"
        blocked=$((blocked + 1))
    done <<< "$ports"

    printf '%s scan done: %d active local port(s) seen, %d newly blocked\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$found" "$blocked" >> "$MONITOR_LOG"
    return 0
}

# Manual unblock (CLI)
unblock_port_now() {
    local port="$1"
    is_valid_port "$port" || die "usage: monitor.sh --unblock <port>"
    ensure_dirs
    if have_ufw; then
        ufw delete deny "$port"/tcp >/dev/null 2>&1 || true
        ufw delete deny "$port"/udp >/dev/null 2>&1 || true
    fi
    [ -f "$BLOCK_LIST_FILE" ] && sed -i "/|${port}\$/d" "$BLOCK_LIST_FILE" 2>/dev/null || true
    log_action "UNBLOCK" "$port" "manual unblock via CLI"
    ok "Port $port unblocked."
}

# Show current monitor status
show_status() {
    ensure_dirs
    echo "=== rogue-port monitor ==="
    load_allowed_ports
    echo "Allowed ports : ${ALLOWED_PORTS[*]:-none}"
    echo "Block window  : ${BLOCK_SECONDS}s"
    if [ -f "$BLOCK_LIST_FILE" ] && [ -s "$BLOCK_LIST_FILE" ]; then
        echo "Currently blocked:"
        local now ts port remain
        now="$(date +%s)"
        while IFS='|' read -r ts port || [ -n "${ts:-}" ]; do
            [ -z "${ts:-}" ] && continue
            remain=$(( BLOCK_SECONDS - (now - ts) ))
            [ "$remain" -lt 0 ] && remain=0
            printf '  - port %s (unblocks in %dm%02ds)\n' "$port" $((remain / 60)) $((remain % 60))
        done < "$BLOCK_LIST_FILE"
    else
        echo "Currently blocked: none"
    fi
    [ -f "$MONITOR_LOG" ] && { echo; echo "Last monitor events:"; tail -n 8 "$MONITOR_LOG"; }
    return 0
}

case "${1:-}" in
    --scan)    run_scan ;;
    --status)  show_status ;;
    --unblock) shift; unblock_port_now "${1:-}" ;;
    *) die "usage: monitor.sh (--scan|--status|--unblock <port>)" ;;
esac
