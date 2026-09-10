#!/usr/bin/env bash
# ============================================================
# vps-security — periodic maintenance
#
# Runs every 2 days (systemd timer, Persistent=true):
#   1. Clear the RAM cache (drop_caches 1 -> 2 -> 3, synced)
#   2. OPTIONAL: clear swap (swapoff -a && swapon -a) — see
#      MAINT_CLEAR_SWAP below. Off by default: on a busy VPS,
#      swapoff can trigger the OOM killer and kill sshd/apps.
#   3. Remove rotated logs (*.gz, *.[0-9]) and truncate the
#      usual suspects (auth.log, syslog, kern.log, ufw.log, ...)
#   4. Vacuum the systemd journal (biggest log consumer)
#
# Env overrides (sandbox/testing):
#   MAINT_LOG_DIR       log directory to clean   (default /var/log)
#   MAINT_CLEAR_SWAP    1 = enable swap clear    (default 0)
#   MAINT_VACUUM_JOURNAL 1 = journalctl vacuum  (default 1)
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

MAINT_LOG_DIR="${MAINT_LOG_DIR:-/var/log}"
MAINT_CLEAR_SWAP="${MAINT_CLEAR_SWAP:-0}"
MAINT_VACUUM_JOURNAL="${MAINT_VACUUM_JOURNAL:-1}"
MAINT_LOG="$VPSSEC_STATE_DIR/maintain.log"

maint_log() {
    ensure_dirs
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$MAINT_LOG"
}

dir_bytes() {
    [ -d "$1" ] && du -sb "$1" 2>/dev/null | awk '{print $1}' || echo 0
}

run_maintenance() {
    ensure_dirs
    local before after freed
    before="$(dir_bytes "$MAINT_LOG_DIR")"

    # ---- 1. RAM cache ----
    sync 2>/dev/null || true
    echo 1 > /proc/sys/vm/drop_caches 2>/dev/null || true
    echo 2 > /proc/sys/vm/drop_caches 2>/dev/null || true
    sync 2>/dev/null || true
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    maint_log "RAM cache cleared (drop_caches 1-3)"

    # ---- 2. swap (optional — dangerous on busy VPS) ----
    if [ "$MAINT_CLEAR_SWAP" = "1" ]; then
        if swapoff -a 2>/dev/null && swapon -a 2>/dev/null; then
            maint_log "Ram-cache and Swap Cleared"
        else
            maint_log "swap clear failed (skipped)"
        fi
    fi

    # ---- 3. rotated + active logs ----
    rm -f "$MAINT_LOG_DIR"/*.gz 2>/dev/null || true
    rm -f "$MAINT_LOG_DIR"/*.[0-9] 2>/dev/null || true
    for f in auth.log syslog kern.log dpkg.log cloud-init.log \
             cloud-init-output.log ufw.log; do
        [ -f "$MAINT_LOG_DIR/$f" ] && truncate -s 0 "$MAINT_LOG_DIR/$f" 2>/dev/null || true
    done
    find "$MAINT_LOG_DIR" -type f \( -name "*.log" -o -name "syslog" \
        -o -name "auth.log" -o -name "kern.log" \) \
        -exec truncate -s 0 {} \; 2>/dev/null || true
    maint_log "rotated logs removed and active logs truncated"

    # ---- 4. journald ----
    if [ "$MAINT_VACUUM_JOURNAL" = "1" ] && command -v journalctl >/dev/null 2>&1; then
        journalctl --vacuum-size=200M >/dev/null 2>&1 || true
        maint_log "journal vacuumed to 200M"
    fi

    after="$(dir_bytes "$MAINT_LOG_DIR")"
    freed=$((before - after))
    [ "$freed" -lt 0 ] && freed=0
    maint_log "maintenance finished (freed ~$((freed / 1024)) KB in $MAINT_LOG_DIR)"
    ok "Maintenance finished (freed ~$((freed / 1024)) KB of logs)."
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
    [ -f "$MAINT_LOG" ] && { echo "Last runs:"; tail -n 6 "$MAINT_LOG" | sed 's/^/  /'; }
    return 0
}

case "${1:-}" in
    --run)    run_maintenance ;;
    --status) maint_status ;;
    *) die "usage: maintain.sh (--run|--status)" ;;
esac
