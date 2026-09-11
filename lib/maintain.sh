#!/usr/bin/env bash
# ============================================================
# vps-security — periodic maintenance
#
# Runs every 2 days (systemd timer, Persistent=true).
# Goal: keep the server lean and fast WITHOUT ever harming it.
#
# Steps:
#   1. Clear the RAM cache (drop_caches 1 -> 2 -> 3, synced)
#   2. OPTIONAL: clear swap (swapoff -a && swapon -a) — see
#      MAINT_CLEAR_SWAP below. Off by default: on a busy VPS,
#      swapoff can trigger the OOM killer and kill sshd/apps.
#   3. Remove rotated logs (*.gz, *.[0-9]) and truncate active
#      system logs. PROTECTED (never touched):
#        - anything inside subdirectories (nginx/, apache2/, …)
#        - every file matching *vps-security* (our own logs —
#          truncating them would corrupt the audit trail)
#        - any top-level *.log named in MAINT_EXCLUDE
#   4. Vacuum the systemd journal to MAINT_JOURNAL_MAX (bytes)
#      AND MAINT_JOURNAL_MAX_TIME (age) — both caps together
#      keep journald bounded even under log floods.
#
# Env overrides:
#   MAINT_LOG_DIR            dir to clean (default /var/log)
#   MAINT_CLEAR_SWAP         1 = enable swap clear (default 0)
#   MAINT_VACUUM_JOURNAL     1 = journalctl vacuum (default 1)
#   MAINT_JOURNAL_MAX        size cap for the journal (default 200M)
#   MAINT_JOURNAL_MAX_TIME   age cap for the journal (default 7d)
#   MAINT_EXCLUDE            extra top-level log names to skip,
#                            comma-separated (e.g. "app.log,panel.log")
#
# Rotation policy note: rotated logs (*.gz, *.1 …) are deleted on
# purpose — logrotate recreates them on the next rotation, so
# nothing breaks; they are pure dead weight on disk.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MAINT_LOG_DIR="${MAINT_LOG_DIR:-/var/log}"
MAINT_CLEAR_SWAP="${MAINT_CLEAR_SWAP:-0}"
MAINT_VACUUM_JOURNAL="${MAINT_VACUUM_JOURNAL:-1}"
MAINT_JOURNAL_MAX="${MAINT_JOURNAL_MAX:-200M}"
MAINT_JOURNAL_MAX_TIME="${MAINT_JOURNAL_MAX_TIME:-7d}"
MAINT_EXCLUDE="${MAINT_EXCLUDE:-}"
MAINT_LOG="$VPSSEC_STATE_DIR/maintain.log"

# Our own logs must survive maintenance — they are the audit trail
# for the monitor, shield, geo filter and maintenance itself.
EXCLUDE_PATTERNS=(*vps-security* monitor.log maintain.log shield-bans.log \
                  shield-blocks.log geo.log port-blocks.log)

maint_log() {
    ensure_dirs
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$MAINT_LOG"
}

dir_bytes() {
    [ -d "$1" ] && du -sb "$1" 2>/dev/null | awk '{print $1}' || echo 0
}

# Is a top-level log protected from truncation?
log_is_protected() {
    local f="$1" p
    for p in "${EXCLUDE_PATTERNS[@]}"; do
        case "$f" in $p) return 0 ;; esac
    done
    if [ -n "$MAINT_EXCLUDE" ]; then
        local IFS=','
        for p in $MAINT_EXCLUDE; do
            [ -z "$p" ] && continue
            [ "$f" = "$p" ] && return 0
        done
    fi
    return 1
}

run_maintenance() {
    ensure_dirs
    local before after freed

    # ---- 1. RAM cache ----
    sync 2>/dev/null || true
    echo 1 > /proc/sys/vm/drop_caches 2>/dev/null \
        && echo 2 > /proc/sys/vm/drop_caches 2>/dev/null \
        && sync 2>/dev/null || true
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    if [ -w /proc/sys/vm/drop_caches ]; then
        maint_log "RAM cache cleared (drop_caches 1-3)"
    else
        maint_log "RAM cache: /proc/sys/vm/drop_caches not writable (container?) — skipped"
    fi

    # ---- 2. swap (optional — dangerous on busy VPS) ----
    if [ "$MAINT_CLEAR_SWAP" = "1" ]; then
        if swapoff -a 2>/dev/null && swapon -a 2>/dev/null; then
            maint_log "Ram-cache and Swap Cleared"
        else
            maint_log "swap clear failed (skipped)"
        fi
    fi

    # ---- 3. rotated + active logs ----
    before="$(dir_bytes "$MAINT_LOG_DIR")"
    # rotated logs are dead weight — logrotate recreates them
    rm -f "$MAINT_LOG_DIR"/*.gz 2>/dev/null || true
    rm -f "$MAINT_LOG_DIR"/*.[0-9] 2>/dev/null || true
    # usual system suspects (top level only, truncation is safe for
    # files that daemons keep open — unlike rm, no fd confusion)
    for f in auth.log syslog kern.log dpkg.log cloud-init.log \
             cloud-init-output.log ufw.log; do
        [ -f "$MAINT_LOG_DIR/$f" ] && truncate -s 0 "$MAINT_LOG_DIR/$f" 2>/dev/null || true
    done
    # every other top-level *.log, except protected files
    local f base
    for f in "$MAINT_LOG_DIR"/*.log; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"
        if log_is_protected "$base"; then
            continue
        fi
        truncate -s 0 "$f" 2>/dev/null || true
    done
    after="$(dir_bytes "$MAINT_LOG_DIR")"
    freed=$((before - after))
    [ "$freed" -lt 0 ] && freed=0
    maint_log "rotated logs removed and active logs truncated (freed ~$((freed / 1024)) KB in $MAINT_LOG_DIR)"

    # ---- 4. journald (biggest log consumer) ----
    if [ "$MAINT_VACUUM_JOURNAL" = "1" ] && command -v journalctl >/dev/null 2>&1; then
        local j_before j_after
        j_before="$(journalctl -o json --no-pager 2>/dev/null | awk '{s += length($0) + 1} END {print s + 0}')"
        journalctl --vacuum-size="$MAINT_JOURNAL_MAX" \
                   --vacuum-time="$MAINT_JOURNAL_MAX_TIME" >/dev/null 2>&1 || true
        j_after="$(journalctl -o json --no-pager 2>/dev/null | awk '{s += length($0) + 1} END {print s + 0}')"
        if [ "${j_after:-0}" -le "${j_before:-0}" ] 2>/dev/null; then
            maint_log "journal vacuumed to $MAINT_JOURNAL_MAX / $MAINT_JOURNAL_MAX_TIME (freed ~$(( (j_before - j_after) / 1024 )) KB)"
        else
            maint_log "journal vacuum ran (size before run not measurable)"
        fi
    fi

    ok "Maintenance finished (freed ~$((freed / 1024)) KB of logs)."
    maint_log "maintenance finished"
    return 0
}

maint_status() {
    ensure_dirs
    echo "=== Maintenance (RAM cache & log cleanup) ==="
    if [ -f "$VPSSEC_SYSTEMD_DIR/vps-security-maint.timer" ]; then
        echo "State        : ENABLED (every 2 days)"
    else
        echo "State        : not installed"
    fi
    echo "Swap clear   : $([ "$MAINT_CLEAR_SWAP" = "1" ] && echo enabled || echo "disabled (recommended on VPS)")"
    echo "Log dir      : $MAINT_LOG_DIR"
    echo "Journal cap  : $MAINT_JOURNAL_MAX / $MAINT_JOURNAL_MAX_TIME"
    [ -n "$MAINT_EXCLUDE" ] && echo "Extra skip   : $MAINT_EXCLUDE"
    [ -f "$MAINT_LOG" ] && { echo "Last runs:"; tail -n 6 "$MAINT_LOG" | sed 's/^/  /'; }
    return 0
}

case "${1:-}" in
    --run)    run_maintenance ;;
    --status) maint_status ;;
    *) die "usage: maintain.sh (--run|--status)" ;;
esac
