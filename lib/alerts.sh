#!/usr/bin/env bash
# ============================================================
# vps-security — pending security alerts (approve before you ban)
#
# The monitor and the shield never punish a host on their own. They
# DETECT suspicious behaviour, write it here as a pending alert and tell
# the administrator. Nothing is firewalled until a human approves it:
#
#   🚨 IP 203.0.113.5 (Netherlands) is flooding port 22 (SSH) —
#      45 new connections in 30s. Ban it?   [y/n]
#
# That is deliberate. A busy-but-legitimate process looks exactly like an
# attack (a tunnel peer opening many connections, a monitoring agent, a
# game server behind a proxy), and a wrong autonomous ban is very hard to
# notice from the outside. Approval keeps false positives recoverable:
# every approved ban lasts 24 hours by default and can be released at any
# moment with the existing unban/unblock commands.
#
# Alert line format (all fields pipe separated, evidence never contains |):
#   <unix-ts>|<kind>|<target>|<country>|<port>|<evidence>
#     kind = ip    -> target is the offending IP, port is the port it hit
#     kind = port  -> target is the rogue port carrying traffic
#
# Usage:
#   alerts.sh --report <ip|port> <target> [port] [evidence]   record one
#   alerts.sh --list                     numbered human list
#   alerts.sh --count                    number of pending alerts
#   alerts.sh --get <n>                  raw line of alert n (for scripts)
#   alerts.sh --describe <n>             one-line description of alert n
#   alerts.sh --approve <n>              apply the ban/block (default 24h)
#   alerts.sh --approve-all              approve every pending alert
#   alerts.sh --dismiss <n>              forget alert n, no firewall change
#   alerts.sh --dismiss-all              forget everything pending
#   alerts.sh --prune                    drop alerts already resolved/expired
#   alerts.sh --motd                     login-notice text (empty if none)
#   alerts.sh --health                   exit 0 when alerts are pending
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

ALERTS_FILE="$VPSSEC_STATE_DIR/pending-alerts.list"
ALERT_LOG="$VPSSEC_STATE_DIR/alerts.log"
SHIELD_CONF="$VPSSEC_CONF_DIR/botshield.conf"
GEO_DIR="$VPSSEC_STATE_DIR/geo"
IPSET_DIR="$VPSSEC_STATE_DIR/geo"

# How long an approved ban lasts. 24 hours by default — long enough to
# stop a campaign, short enough that a mistake is not permanent, and it
# can always be released early (vpssec shield unban / vpssec unblock).
APPROVAL_BAN_SECONDS="${APPROVAL_BAN_SECONDS:-86400}"
BLOCK_SECONDS="${BLOCK_SECONDS:-$APPROVAL_BAN_SECONDS}"
BAN_SECONDS="${BAN_SECONDS:-$APPROVAL_BAN_SECONDS}"
# Alerts nobody acted on are forgotten after a week.
ALERT_TTL_SECONDS="${ALERT_TTL_SECONDS:-604800}"
ALERT_MAX_ENTRIES="${ALERT_MAX_ENTRIES:-200}"

alert_log() {
    ensure_dirs
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$ALERT_LOG"
}

# ---------- country of an IP (best effort, never fatal) ----------

# Prints a 2-letter code, or nothing when it cannot be determined.
# Sources, in order: geoiplookup (if the admin installed it), then the
# offline country CIDR lists the GeoIP filter already downloaded.
ip_country() {
    local ip="$1" cc="" python_bin
    case "$ip" in ''|127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|169.254.*) return 0 ;; esac

    if command -v geoiplookup >/dev/null 2>&1; then
        cc="$(geoiplookup "$ip" 2>/dev/null | head -1 | sed -n 's/^[^:]*: *\([A-Za-z]\{2\}\),.*/\1/p')"
        [ -n "$cc" ] && { printf '%s' "$cc"; return 0; }
    fi

    python_bin="$(command -v python3 || true)"
    if [ -n "$python_bin" ] && [ -d "$GEO_DIR" ]; then
        cc="$("$python_bin" - "$GEO_DIR" "$ip" <<'PY' 2>/dev/null
import ipaddress, os, sys
geo_dir, raw = sys.argv[1], sys.argv[2]
try:
    addr = ipaddress.ip_address(raw)
except ValueError:
    sys.exit(0)
for name in sorted(os.listdir(geo_dir)):
    if not name.endswith(".cidr"):
        continue
    try:
        with open(os.path.join(geo_dir, name)) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    if addr in ipaddress.ip_network(line, strict=False):
                        print(name[:-5].upper())
                        sys.exit(0)
                except ValueError:
                    continue
    except OSError:
        continue
PY
)"
    fi
    printf '%s' "$cc"
}

# Human country name for a code ("NL" -> "Netherlands"), from the GeoIP
# country table so the two features can never disagree.
country_name() {
    local cc="$1" name=""
    [ -z "$cc" ] && return 0
    case "$cc" in -|unknown) return 0 ;; esac
    name="$(bash "$SCRIPT_DIR/lib/geoip.sh" --cc-name "$cc" 2>/dev/null | head -1)"
    printf '%s' "${name:-$cc}"
}

# ---------- the queue ----------

alert_entries() {
    [ -f "$ALERTS_FILE" ] || return 0
    grep -E '^[0-9]+\|' "$ALERTS_FILE" 2>/dev/null || true
}

alert_count() {
    alert_entries | wc -l | tr -d ' '
}

# Raw line of alert number $1 (1-based), empty when out of range.
alert_line() {
    local want="$1" n=0 line
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        n=$((n + 1))
        [ "$n" -eq "$want" ] && { printf '%s\n' "$line"; return 0; }
    done < <(alert_entries)
    return 0
}

alert_field() {
    local line="$1" field="$2"
    case "$field" in
        ts)       printf '%s' "${line%%|*}" ;;
        kind)     printf '%s' "$(printf '%s' "$line" | cut -d'|' -f2)" ;;
        target)   printf '%s' "$(printf '%s' "$line" | cut -d'|' -f3)" ;;
        country)  printf '%s' "$(printf '%s' "$line" | cut -d'|' -f4)" ;;
        port)     printf '%s' "$(printf '%s' "$line" | cut -d'|' -f5)" ;;
        evidence) printf '%s' "$(printf '%s' "$line" | cut -d'|' -f6-)" ;;
    esac
}

human_age() {
    local ts="$1" now secs
    now="$(date +%s)"
    secs=$((now - ts))
    [ "$secs" -lt 0 ] && secs=0
    if [ "$secs" -lt 60 ]; then printf 'just now'
    elif [ "$secs" -lt 3600 ]; then printf '%dm ago' $((secs / 60))
    elif [ "$secs" -lt 86400 ]; then printf '%dh ago' $((secs / 3600))
    else printf '%dd ago' $((secs / 86400))
    fi
}

# One-line human description of an alert line.
alert_describe() {
    local line="$1" kind target country port evidence ccname who
    kind="$(alert_field "$line" kind)"
    target="$(alert_field "$line" target)"
    country="$(alert_field "$line" country)"
    port="$(alert_field "$line" port)"
    evidence="$(alert_field "$line" evidence)"
    if [ "$kind" = "ip" ]; then
        ccname="$(country_name "$country")"
        who="IP $target"
        [ -n "$ccname" ] && who="$who ($ccname)"
        [ -n "$port" ] && who="$who hitting port $port"
    else
        who="Port $target"
    fi
    printf '%s — %s (%s)' "$who" "${evidence:-suspicious activity}" "$(human_age "$(alert_field "$line" ts)")"
}

alert_exists() {
    local kind="$1" target="$2" line
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        [ "$(alert_field "$line" kind)" = "$kind" ] && \
        [ "$(alert_field "$line" target)" = "$target" ] && return 0
    done < <(alert_entries)
    return 1
}

# Is this target already punished? A pending alert for something that is
# already banned/blocked is noise.
alert_target_resolved() {
    local kind="$1" target="$2"
    if [ "$kind" = "ip" ]; then
        [ -f "$VPSSEC_STATE_DIR/shield-bans.list" ] && \
            grep -qF "|$target" "$VPSSEC_STATE_DIR/shield-bans.list" && return 0
    else
        port_is_blocked "$target" && return 0
    fi
    return 1
}

# Drop resolved, expired and duplicate entries. Safe to call any time.
alert_prune() {
    [ -f "$ALERTS_FILE" ] || return 0
    ensure_dirs
    local now tmp line kind target ts kept=0
    now="$(date +%s)"
    tmp="$(mktemp)"
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        ts="$(alert_field "$line" ts)"
        kind="$(alert_field "$line" kind)"
        target="$(alert_field "$line" target)"
        # keep only well-formed, unexpired, still-relevant entries
        case "$ts" in ''|*[!0-9]*) continue ;; esac
        [ $((now - ts)) -ge "$ALERT_TTL_SECONDS" ] && continue
        alert_target_resolved "$kind" "$target" && continue
        printf '%s\n' "$line" >> "$tmp"
        kept=$((kept + 1))
    done < <(alert_entries)
    mv "$tmp" "$ALERTS_FILE"
    [ -f "$ALERTS_FILE" ] || : > "$ALERTS_FILE"
    return 0
}

# Remove one alert by kind+target.
alert_remove() {
    local kind="$1" target="$2" line tmp
    [ -f "$ALERTS_FILE" ] || return 0
    tmp="$(mktemp)"
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        if [ "$(alert_field "$line" kind)" = "$kind" ] && \
           [ "$(alert_field "$line" target)" = "$target" ]; then
            continue
        fi
        printf '%s\n' "$line" >> "$tmp"
    done < "$ALERTS_FILE"
    mv "$tmp" "$ALERTS_FILE"
}

# ---------- recording ----------

# alert_add <ip|port> <target> [port] [evidence]
#
# Safety: nothing that could carry normal control traffic is ever queued —
# loopback/private peers and trusted (GeoIP bypass) IPs for the ip kind,
# and allow-listed or tunnel ports for the port kind. That is what keeps
# "an IP/port used by a normal process" out of the ban path.
alert_add() {
    local kind="$1" target="$2" port="${3:-}" evidence="${4:-}" country="-" line
    ensure_dirs
    case "$kind" in ip|port) ;; *) die "alerts.sh: kind must be ip or port" ;; esac
    [ -z "$target" ] && return 0
    evidence="${evidence//|//}"

    if [ "$kind" = "ip" ]; then
        printf '%s' "$target" | grep -qE '^[0-9a-fA-F.:]+$' || return 0
        ip_is_local "$target" && {
            alert_log "SKIP local/private peer $target"
            return 0
        }
        while IFS= read -r t; do
            [ -n "$t" ] && [ "$t" = "$target" ] && {
                alert_log "SKIP trusted peer $target"
                return 0
            }
        done < <(trusted_ip_list)
        country="$(ip_country "$target")"
        [ -z "$country" ] && country="-"
    else
        is_valid_port "$target" || return 0
        load_allowed_ports
        load_tunnel_ports
        port_is_allowed "$target" && { alert_log "SKIP allowed port $target"; return 0; }
        port_is_tunnel "$target" && { alert_log "SKIP tunnel port $target"; return 0; }
    fi

    alert_target_resolved "$kind" "$target" && { alert_log "SKIP already punished $kind $target"; return 0; }
    if alert_exists "$kind" "$target"; then
        alert_log "STILL-PENDING $kind $target"
        return 0
    fi

    alert_prune >/dev/null 2>&1 || true
    line="$(printf '%s|%s|%s|%s|%s|%s' "$(date +%s)" "$kind" "$target" "$country" "${port:-}" "$evidence")"
    printf '%s\n' "$line" >> "$ALERTS_FILE"

    # Cap the queue so a flood cannot grow the file forever.
    local total
    total="$(alert_count)"
    if [ "$total" -gt "$ALERT_MAX_ENTRIES" ]; then
        tail -n "$ALERT_MAX_ENTRIES" "$ALERTS_FILE" > "$ALERTS_FILE.tmp" && mv "$ALERTS_FILE.tmp" "$ALERTS_FILE"
    fi
    alert_log "DETECTED $kind $target port=${port:--} country=$country :: $evidence"
    alert_notify "$line"
}

# Human notice for a freshly detected alert (also lands in the journal when
# the monitor timer runs it).
alert_notify() {
    local line="$1"
    printf '%b\n' "${YELLOW}[!] Suspicious activity detected:${RESET} $(alert_describe "$line")"
    printf '%b\n' "    ${DIM}Nothing was blocked. Review and ban with:${RESET} sudo vpssec alerts"
}

# ---------- approve / dismiss ----------

# Apply the punishment for an alert line. Returns 0 when it was applied.
alert_apply() {
    local line="$1" kind target
    kind="$(alert_field "$line" kind)"
    target="$(alert_field "$line" target)"
    if [ "$kind" = "ip" ]; then
        BAN_SECONDS="$BAN_SECONDS" bash "$SCRIPT_DIR/lib/botshield.sh" --ban-now "$target" \
            "approved by admin" || return 1
        ok "IP $target banned for $((BAN_SECONDS / 3600))h. Release early: sudo vpssec shield unban"
    else
        BLOCK_SECONDS="$BLOCK_SECONDS" bash "$SCRIPT_DIR/lib/monitor.sh" --block-now "$target" \
            "approved by admin" || return 1
        ok "Port $target blocked for $((BLOCK_SECONDS / 3600))h. Release early: sudo vpssec unblock $target"
    fi
    alert_remove "$kind" "$target"
    alert_log "APPROVED $kind $target (${BAN_SECONDS}s)"
    return 0
}

alert_dismiss() {
    local line="$1" kind target
    kind="$(alert_field "$line" kind)"
    target="$(alert_field "$line" target)"
    alert_remove "$kind" "$target"
    alert_log "DISMISSED $kind $target (no firewall change)"
    info "Alert dismissed for $( [ "$kind" = "ip" ] && printf 'IP %s' "$target" || printf 'port %s' "$target" ) — nothing was blocked."
}

# ---------- output ----------

alert_list() {
    ensure_dirs
    alert_prune >/dev/null 2>&1 || true
    local n=0 line
    if [ "$(alert_count)" -eq 0 ]; then
        info "No pending alerts — nothing is waiting for your approval. ✓"
        return 0
    fi
    printf '  %b\n' "${BOLD}Pending security alerts ($(alert_count)) — nothing is blocked yet${RESET}"
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        n=$((n + 1))
        printf '  %2d) 🚨 %s\n' "$n" "$(alert_describe "$line")"
    done < <(alert_entries)
    printf '  %b\n' "${DIM}Approve one: sudo vpssec alerts approve <n>   ·   forget it: sudo vpssec alerts dismiss <n>${RESET}"
}

alert_motd() {
    local n
    n="$(alert_count)"
    [ "${n:-0}" -eq 0 ] && return 0
    printf '\n'
    printf '  ⚠  %s suspicious network event(s) await YOUR approval — nothing is blocked yet\n' "$n"
    local i=0 line
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        i=$((i + 1))
        [ "$i" -gt 3 ] && break
        printf '       · %s\n' "$(alert_describe "$line")"
    done < <(alert_entries)
    [ "$n" -gt 3 ] && printf '       · ...and %s more\n' "$((n - 3))"
    printf '     Review / ban now:  sudo vpssec alerts\n\n'
}

case "${1:-}" in
    --report)
        shift
        need_root
        alert_add "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
    --list)        alert_list ;;
    --count)       alert_count ;;
    --get)
        shift
        alert_line "${1:-}" ;;
    --describe)
        shift
        line="$(alert_line "${1:-}")"
        [ -n "$line" ] && alert_describe "$line" ;;
    --approve)
        shift
        need_root
        line="$(alert_line "${1:-}")"
        [ -z "$line" ] && die "No pending alert number ${1:-}."
        alert_apply "$line" ;;
    --approve-all)
        need_root
        alert_prune >/dev/null 2>&1 || true
        [ "$(alert_count)" -eq 0 ] && { info "Nothing pending."; exit 0; }
        applied=0
        while line="$(alert_line 1)" && [ -n "$line" ]; do
            alert_apply "$line" || break
            applied=$((applied + 1))
        done
        ok "$applied alert(s) approved." ;;
    --dismiss)
        shift
        need_root
        line="$(alert_line "${1:-}")"
        [ -z "$line" ] && die "No pending alert number ${1:-}."
        alert_dismiss "$line" ;;
    --dismiss-all)
        need_root
        while line="$(alert_line 1)" && [ -n "$line" ]; do
            alert_dismiss "$line"
        done
        alert_prune >/dev/null 2>&1 || true ;;
    --prune)  need_root; alert_prune; ok "Alert queue pruned ($(alert_count) pending)." ;;
    --motd)   alert_motd ;;
    --health) [ "$(alert_count)" -gt 0 ] ;;
    *) die "usage: alerts.sh (--report <ip|port> <target> [port] [evidence]|--list|--count|--get <n>|--describe <n>|--approve <n>|--approve-all|--dismiss <n>|--dismiss-all|--prune|--motd|--health)" ;;
esac
