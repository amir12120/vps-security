#!/bin/sh
# ============================================================
# vps-security — login notice for pending security alerts
#
# Installed as /etc/update-motd.d/99-vps-security-alerts so the
# administrator sees suspicious activity the moment they log in —
# nothing is blocked until they approve it, so silence would be the
# worst outcome.
#
# Deliberately POSIX sh with no library dependencies: it runs on every
# SSH login and must never slow a session down or fail loudly.
# Removed by "sudo vpssec uninstall".
# ============================================================

STATE="${VPSSEC_STATE_DIR:-/var/lib/vps-security}"
ALERTS="$STATE/pending-alerts.list"

[ -f "$ALERTS" ] || exit 0

n=$(grep -c '^[0-9][0-9]*|' "$ALERTS" 2>/dev/null)
[ -n "$n" ] || n=0
[ "$n" -gt 0 ] 2>/dev/null || exit 0

printf '\n'
printf '  ⚠  %s suspicious network event(s) await YOUR approval — nothing is blocked yet\n' "$n"
awk -F'|' -v n="$n" '
    NR <= 3 {
        if ($2 == "ip") {
            where = ($4 != "" && $4 != "-") ? " (" $4 ")" : ""
            printf "       · IP %s%s is generating suspicious traffic on port %s\n", $3, where, $5
        } else {
            printf "       · Port %s is carrying traffic outside your allow-list\n", $3
        }
    }
    NR == 4 { printf "       · ...and %d more\n", n - 3 }
' "$ALERTS"
printf '     Review and ban:  sudo vpssec alerts\n\n'

exit 0
