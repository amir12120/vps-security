#!/usr/bin/env bash
# ============================================================
# vps-security — rogue-port monitor
## Every run (systemd timer fires every 30 minutes):
#   1. Unblock any ports whose 1-hour block has expired.
#   2. Scan live sockets (ss -tunap).
#   3. Any port BOUND on a public address that is actively serving
#      traffic and is NOT approved gets BLOCKED via ufw for one hour:
#        - TCP: a LISTEN socket that also has established connections
#        - UDP: a bound socket outside the ephemeral port range
#   4. Skipped: allow-listed ports, declared tunnel ports, the sshd and
#      guard ports, already-blocked ports, loopback-only sockets, and
#      anything the admin has already allowed in ufw.
#
# Outbound sockets are deliberately NOT candidates: their local port is
# a kernel-assigned ephemeral port. On a tunnelled server (the normal
# case) blocking those would break the tunnel and spam ufw with rules.
#
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

# Ports that are BOUND on a non-loopback address, as "proto|port".
#
# Only bound sockets can be services. The local ports of outbound
# connections are kernel-assigned ephemeral ports, and this server very
# likely opens such connections all the time — a tunnel to a foreign
# server, a panel API call, package updates. Blocking those (which the
# old implementation did) breaks tunnels and fills ufw with junk rules.
# ss -tunap fields: $1=netid $2=state $3=recvq $4=sendq $5=local $6=peer
bound_local_ports() {
    have_ss || return 0
    ss_raw | awk '
        function is_loopback(a) {
            return (a ~ /^127\./ || a ~ /^\[::1\]/ || a ~ /^::1:/ || a ~ /^\[::ffff:127\./)
        }
        NR > 1 {
            port = $5
            sub(/.*[:.]/, "", port)
            if (port !~ /^[0-9]+$/) next
            if ($1 == "tcp") {
                if ($2 == "LISTEN" && !is_loopback($5)) print "tcp|" port
            } else if ($1 == "udp") {
                # a bound UDP socket is a service; connected ones are clients
                if ($2 == "UNCONN" && !is_loopback($5)) print "udp|" port
            }
        }
    ' | sort -u || true
}

# Local ports of established TCP connections — proof that a bound port is
# actually serving traffic right now.
serving_local_ports() {
    have_ss || return 0
    ss_raw | awk '
        NR > 1 {
            if ($1 != "tcp" || $2 != "ESTAB") next
            port = $5
            sub(/.*[:.]/, "", port)
            if (port ~ /^[0-9]+$/) print port
        }
    ' | sort -u || true
}

# Ports the administrator already opened in ufw. A port that is allowed
# at the firewall is approval in itself — the monitor must never fight a
# rule the admin set for their own tunnel.
ufw_allowed_ports() {
    have_ufw || return 0
    ufw status 2>/dev/null | awk '
        $2 == "ALLOW" {
            p = $1
            sub(/\/(tcp|udp)$/, "", p)
            if (p ~ /^[0-9]+$/) print p
        }
    ' | sort -u || true
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

# Is this a UDP port that can only belong to a CLIENT socket?
# Ephemeral ports are handed out to outbound sockets, and a few
# protocols (DHCP/NTP) legitimately bind system-wide.
udp_is_client_port() {
    local port="$1" lo p
    lo="$(local_port_range_lo)"
    [ "$port" -ge "$lo" ] && return 0
    for p in $UDP_CLIENT_PORTS; do
        [ "$port" = "$p" ] && return 0
    done
    return 1
}

# Main scan
run_scan() {
    ensure_dirs
    load_allowed_ports
    load_tunnel_ports

    printf '%s scan start (allowed: %s; tunnel: %s)\n' "$(date '+%Y-%m-%d %H:%M:%S')" \
        "${ALLOWED_PORTS[*]:-none}" "${TUNNEL_PORTS[*]:-none}" >> "$MONITOR_LOG"

    unblock_expired

    local bound serving ufw_open proto port found=0 blocked=0
    bound="$(bound_local_ports)"
    [ -z "$bound" ] && return 0
    serving="$(serving_local_ports)"
    ufw_open="$(ufw_allowed_ports)"

    while IFS='|' read -r proto port; do
        [ -z "$port" ] && continue
        found=$((found + 1))
        # The admin's own declarations always win.
        port_is_allowed "$port" && continue
        port_is_tunnel "$port" && {
            printf '%s SKIP %s (declared tunnel port)\n' \
                "$(date '+%Y-%m-%d %H:%M:%S')" "$port" >> "$MONITOR_LOG"
            continue
        }
        port_is_blocked "$port" && continue
        # A port the admin already opened in ufw is approved by definition.
        if [ -n "$ufw_open" ] && printf '%s\n' "$ufw_open" | grep -qx "$port"; then
            continue
        fi
        if [ "$proto" = "tcp" ]; then
            # Only block a service that is demonstrably serving traffic.
            printf '%s\n' "$serving" | grep -qx "$port" || continue
        else
            # UDP has no per-socket activity counter: trust only ports
            # outside the ephemeral range and never block client sockets.
            udp_is_client_port "$port" && continue
        fi
        block_port "$port" "rogue $proto service carrying traffic"
        blocked=$((blocked + 1))
    done <<< "$bound"

    printf '%s scan done: %d bound port(s) seen, %d newly blocked\n' \
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
