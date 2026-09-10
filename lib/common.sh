#!/usr/bin/env bash
# ============================================================
# vps-security — shared helpers
# ============================================================

# Colors (disabled when not a TTY)
if [ -t 1 ]; then
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

# State/config locations
VPSSEC_CONF_DIR="${VPSSEC_CONF_DIR:-/etc/vps-security}"
VPSSEC_STATE_DIR="${VPSSEC_STATE_DIR:-/var/lib/vps-security}"
VPSSEC_SYSTEMD_DIR="${VPSSEC_SYSTEMD_DIR:-/etc/systemd/system}"
MONITOR_CONF="$VPSSEC_CONF_DIR/monitor.conf"
ALLOWED_PORTS_CONF="$VPSSEC_CONF_DIR/allowed-ports.list"
BLOCK_LIST_FILE="$VPSSEC_STATE_DIR/blocked-ports.list"
BLOCK_LOG="$VPSSEC_STATE_DIR/port-blocks.log"

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
