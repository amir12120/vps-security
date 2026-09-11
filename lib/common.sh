#!/usr/bin/env bash
# ============================================================
# vps-security — shared helpers
# ============================================================

# Colors (disabled when not a TTY)
if [ -t 1 ]; then
    # shellcheck disable=SC2034  # BOLD/DIM are consumed by vpssec's TUI which sources this file
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' DIM='' RESET=''
fi

info()  { printf "%b\n" "${CYAN}[i]${RESET} $*"; }
ok()    { printf "%b\n" "${GREEN}[✓]${RESET} $*"; }
warn()  { printf "%b\n" "${YELLOW}[!]${RESET} $*"; }
err()   { printf "%b\n" "${RED}[✗]${RESET} $*" >&2; }

die() { err "$*"; exit 1; }

# Require root (allows CI override for syntax-only checks)
need_root() {
    [ "${VPSSEC_SKIP_ROOT_CHECK:-0}" = "1" ] && return 0
    [ "$(id -u)" -eq 0 ] || die "This command must run as root (try: sudo $0 $*)"
}

# Port sanity check: 1-65535, numeric
is_valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# Split a comma / space separated port list into one valid port per line:
#   while IFS= read -r p; do ... done < <(parse_port_csv "444,2086,2098")
# Invalid tokens are reported on stderr and skipped, so a single prompt can
# collect the whole list at once (444,2086,2098,2689) without losing ports.
parse_port_csv() {
    local raw="$1" tok
    local -a toks=()
    IFS=$' \t\n,;' read -ra toks <<< "$raw"
    for tok in "${toks[@]:-}"; do
        tok="$(printf '%s' "$tok" | tr -d '[:space:]')"
        [ -z "$tok" ] && continue
        if is_valid_port "$tok"; then
            printf '%s\n' "$tok"
        else
            warn "Ignoring invalid port: $tok" >&2
        fi
    done
}

# State/config locations
VPSSEC_CONF_DIR="${VPSSEC_CONF_DIR:-/etc/vps-security}"
VPSSEC_STATE_DIR="${VPSSEC_STATE_DIR:-/var/lib/vps-security}"
VPSSEC_SYSTEMD_DIR="${VPSSEC_SYSTEMD_DIR:-/etc/systemd/system}"
# Where generated ufw 'before' rules live (overridable for sandbox tests)
UFW_DIR="${UFW_DIR:-/etc/ufw}"
# Path overridable for sandbox tests; consumed by lib/monitor.sh (and vpssec)
MONITOR_CONF="$VPSSEC_CONF_DIR/monitor.conf"  # shellcheck disable=SC2034
ALLOWED_PORTS_CONF="$VPSSEC_CONF_DIR/allowed-ports.list"
BLOCK_LIST_FILE="$VPSSEC_STATE_DIR/blocked-ports.list"
BLOCK_LOG="$VPSSEC_STATE_DIR/port-blocks.log"
# Ports that carry tunnels / reverse proxies. They are ordinary allowed
# ports for the firewall, but the monitor never flags them as rogue and
# the shield never rate-limits them: a busy tunnel peer is one IP opening
# many connections, which looks exactly like an attack to `ufw limit`.
TUNNEL_PORTS_CONF="$VPSSEC_CONF_DIR/tunnel-ports.list"
# Client-side protocols that legitimately bind UDP sockets system-wide.
UDP_CLIENT_PORTS="67 68 123 546 547"

ensure_dirs() {
    mkdir -p "$VPSSEC_CONF_DIR" "$VPSSEC_STATE_DIR"
    chmod 700 "$VPSSEC_CONF_DIR" "$VPSSEC_STATE_DIR"
}

# Read newline-separated allowed ports (comments and blanks ignored).
# Populates the global array ALLOWED_PORTS.
load_allowed_ports() {
    ALLOWED_PORTS=()
    if [ -f "$ALLOWED_PORTS_CONF" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line%%#*}"
            line="$(echo "$line" | tr -d '[:space:]')"
            [ -z "$line" ] && continue
            if is_valid_port "$line"; then
                ALLOWED_PORTS+=("$line")
            else
                warn "Ignoring invalid port in $ALLOWED_PORTS_CONF: $line"
            fi
        done < "$ALLOWED_PORTS_CONF"
    fi
}

# Is a port in the allowed list?
port_is_allowed() {
    local p
    for p in "${ALLOWED_PORTS[@]:-}"; do
        [ "$p" = "$1" ] && return 0
    done
    return 1
}

# Read tunnel/proxy ports (comments and blanks ignored). Populates TUNNEL_PORTS.
load_tunnel_ports() {
    TUNNEL_PORTS=()
    [ -f "$TUNNEL_PORTS_CONF" ] || return 0
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -d '[:space:]')"
        [ -z "$line" ] && continue
        is_valid_port "$line" && TUNNEL_PORTS+=("$line")
    done < "$TUNNEL_PORTS_CONF"
    return 0
}

# Is this port declared as a tunnel / reverse-proxy port?
port_is_tunnel() {
    local p
    for p in "${TUNNEL_PORTS[@]:-}"; do
        [ "$p" = "$1" ] && return 0
    done
    return 1
}

# The local port range the kernel hands out to OUTBOUND sockets.
# Outbound client sockets (DNS queries, tunnel connections to a remote
# server) live here, so the monitor must never treat them as services.
local_port_range_lo() {
    local lo=""
    [ -r /proc/sys/net/ipv4/ip_local_port_range ] && \
        read -r lo _ < /proc/sys/net/ipv4/ip_local_port_range
    is_valid_port "${lo:-}" && { printf '%s' "$lo"; return 0; }
    printf '32768'
}

# Is this address inside the server's own private/loopback space?
# Such "peers" are the machine talking to itself or to its LAN — never a
# remote attacker, and on a tunnelled server they are the tunnel itself.
# Nothing in this toolkit may ever ban or block them.
ip_is_local() {
    case "${1:-}" in
        ''|127.*|::1|0.0.0.0|::)                     return 0 ;;
        10.*|192.168.*|169.254.*)                    return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*)       return 0 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[0-2][0-9].*) return 0 ;;
        fe80:*|fc??:*|fd??:*|::ffff:127.*)           return 0 ;;
    esac
    return 1
}

# Trusted peers that must never be banned (read from the GeoIP bypass
# list, which is the toolkit's single "never block this IP" declaration).
trusted_ip_list() {
    local ip
    [ -f "$VPSSEC_CONF_DIR/geo.conf" ] || return 0
    while IFS= read -r ip; do
        [ -n "$ip" ] && printf '%s\n' "$ip"
    done < <(grep -m1 '^GEO_BYPASS=' "$VPSSEC_CONF_DIR/geo.conf" 2>/dev/null \
        | cut -d= -f2- | tr ',' '\n')
    return 0
}

# Is a port currently blocked by the guard? (list lines: <unix-ts>|<port>)
port_is_blocked() {
    [ -f "$BLOCK_LIST_FILE" ] && grep -qE "^[0-9]+\|$1\$" "$BLOCK_LIST_FILE"
}

# Log an action with timestamp
log_action() {
    ensure_dirs
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$BLOCK_LOG"
}

# Debian/Ubuntu check (skippable in sandboxes via VPSSEC_SKIP_OS_CHECK=1)
require_debian_like() {
    [ "${VPSSEC_SKIP_OS_CHECK:-0}" = "1" ] && return 0
    if [ ! -f /etc/debian_version ]; then
        die "This installer supports Debian/Ubuntu systems only."
    fi
}
