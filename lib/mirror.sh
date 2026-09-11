#!/usr/bin/env bash
# ============================================================
# vps-security — The best Iranian mirror & DNS
#
# For servers located in Iran, where direct GitHub access is
# slow or blocked. This module:
#   1. Tests a curated list of IRANIAN GITHUB MIRRORS by timing
#      real git-protocol requests (info/refs) — the mirror with
#      the lowest response time wins.
#   2. Installs the winner system-wide via `git config --system
#      url.<mirror>.insteadOf https://github.com/` so EVERY git
#      clone/pull/fetch (including `vpssec update`) transparently
#      uses the fastest mirror.
#   3. Tests IRANIAN PUBLIC DNS servers by timing real lookups
#      of github.com — the fastest one is applied server-wide
#      (systemd-resolved drop-in, or plain /etc/resolv.conf).
#   4. Can undo everything (`--reset`): removes the insteadOf
#      rewrite and restores the previous DNS configuration.
#
# Choices are persisted in /etc/vps-security/mirror.conf.
#
# Env overrides (sandbox/testing):
#   VPSSEC_GITCONFIG        system gitconfig path (default /etc/gitconfig)
#   VPSSEC_RESOLVED_CONF_D  resolved drop-in dir (default /etc/systemd/resolved.conf.d)
#   VPSSEC_RESOLV_CONF      resolv.conf path (default /etc/resolv.conf)
#   MIRROR_PROBE_REPO       repo used for timing probes
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

MIRROR_CONF="$VPSSEC_CONF_DIR/mirror.conf"
MIRROR_LOG="$VPSSEC_STATE_DIR/mirror.log"
GIT_CONFIG_DIR_DEFAULT="/etc"
RESOLVED_CONF_D="${VPSSEC_RESOLVED_CONF_D:-/etc/systemd/resolved.conf.d}"
RESOLV_CONF="${VPSSEC_RESOLV_CONF:-/etc/resolv.conf}"
PROBE_REPO="${MIRROR_PROBE_REPO:-octocat/Hello-World}"

# ------------------------------------------------------------
# Curated Iranian GitHub mirrors (add new entries here).
#   name|base-url|how-probe-url-is-built
# The probe hits the git smart-HTTP protocol endpoint, which is
# exactly what `git clone/fetch` uses — a true end-to-end test.
# ------------------------------------------------------------
MIRROR_LIST=(
    "gitclone.ir|https://gitclone.ir/github.com|BASE/$PROBE_REPO.git/info/refs?service=git-upload-pack"
    "github.iranserver.com|https://github.iranserver.com|BASE/$PROBE_REPO.git/info/refs?service=git-upload-pack"
    "gitdl.theazizi.ir|https://gitdl.theazizi.ir|BASE/https://github.com/$PROBE_REPO/archive/refs/heads/master.tar.gz"
)

# Curated Iranian public DNS providers (primary|secondary|name).
# These resolvers are well known for serving GitHub from inside Iran.
DNS_LIST=(
    "178.22.122.100|185.51.200.2|Shecan"
    "10.202.10.202|10.202.10.102|403.online"
    "10.202.10.10|10.202.10.11|Radar"
    "185.55.226.26|185.55.225.25|Begzar"
    "78.157.42.100|78.157.42.101|Electro"
    "5.202.100.100|5.202.100.101|Pishgaman"
    "94.103.125.157|94.103.125.158|Shelter"
)

now_ms() { date +%s%3N; }

# local yes/no prompt (self-contained so lib/ works without the CLI)
mirror_confirm() {
    local answer=""
    printf '%s' "$1"
    IFS= read -r answer
    case "$answer" in
        ''|[Yy]|[Yy][Ee][Ss]) return 0 ;;
        *) return 1 ;;
    esac
}

log_mirror() {
    ensure_dirs
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$MIRROR_LOG"
}

# ---------- persistence ----------

load_mirror_conf() {
    MIRROR_NAME="" MIRROR_BASE="" DNS_NAME="" DNS_PRIMARY="" DNS_SECONDARY=""
    [ -f "$MIRROR_CONF" ] && . "$MIRROR_CONF" 2>/dev/null
    return 0
}

save_mirror_conf() {
    ensure_dirs
    cat > "$MIRROR_CONF" <<EOF
MIRROR_NAME=${MIRROR_NAME:-}
MIRROR_BASE=${MIRROR_BASE:-}
DNS_NAME=${DNS_NAME:-}
DNS_PRIMARY=${DNS_PRIMARY:-}
DNS_SECONDARY=${DNS_SECONDARY:-}
EOF
    chmod 644 "$MIRROR_CONF"
}

# ---------- mirror testing ----------

# probe <url>  -> prints total seconds (e.g. 0.372) or nothing on failure
probe_url() {
    local out
    out="$(curl -o /dev/null -fsSL --max-time 8 -w '%{http_code} %{time_total}' "$1" 2>/dev/null)" || return 1
    [ "${out%% *}" = "200" ] || return 1
    printf '%s\n' "${out#* }"
}

# Times every mirror against GitHub; prints "time|name|base" sorted best-first
# NOTE: the human-readable table goes to stderr so callers can capture the
#       winner lines from stdout without losing the speed-test display.
test_mirrors() {
    local entry name base url t direct_ms
    echo "=== GitHub mirror speed test (criterion: GitHub access time) ===" >&2
    echo >&2

    # baseline: direct github.com
    local d_start d_end
    d_start="$(now_ms)"
    if curl -o /dev/null -fsSL --max-time 8 "https://github.com/$PROBE_REPO" >/dev/null 2>&1; then
        d_end="$(now_ms)"
        direct_ms=$((d_end - d_start))
        printf '  %-28s %6d ms   %s\n' "(direct github.com)" "$direct_ms" "baseline" >&2
    else
        printf '  %-28s %6s     %s\n' "(direct github.com)" "FAIL" "baseline" >&2
    fi
    echo >&2

    local results=()
    for entry in "${MIRROR_LIST[@]}"; do
        name="${entry%%|*}"; rest="${entry#*|}"
        base="${rest%%|*}"; tpl="${rest#*|}"
        url="${tpl/BASE/$base}"
        printf '  testing %-28s ... ' "$name" >&2
        t="$(probe_url "$url")"
        if [ -n "$t" ]; then
            local ms=$(( $(echo "$t" | awk '{printf "%d", $1 * 1000}') ))
            printf '%6d ms   OK\n' "$ms" >&2
            results+=("${ms}|${name}|${base}")
        else
            printf '   FAIL  (unreachable)\n' >&2
        fi
    done

    [ "${#results[@]}" -eq 0 ] && { echo >&2; err "No Iranian mirror answered — nothing to install."; return 1; }
    printf '%s\n' "${results[@]}" | sort -t'|' -k1,1n
}

# ---------- DNS testing ----------

dns_query_ms() {
    local ns="$1" host="$2" out
    command -v dig >/dev/null 2>&1 || return 1
    out="$(dig "@$ns" "$host" +tries=1 +time=3 +noall +comments +answer 2>/dev/null)" || return 1
    echo "$out" | grep -q 'status: NOERROR' || return 1
    echo "$out" | grep -qE '^[^;].*\sA\s' || return 1
    echo "$out" | awk '/Query time:/ {print $4; exit}'
}

# Times every DNS against github.com; prints "ms|name|primary|secondary" best-first
test_dns() {
    local entry primary secondary name ms
    echo >&2
    echo "=== Iranian DNS speed test (criterion: github.com resolution time) ===" >&2
    echo >&2
    local results=()
    for entry in "${DNS_LIST[@]}"; do
        primary="${entry%%|*}"; rest="${entry#*|}"
        secondary="${rest%%|*}"; name="${rest#*|}"
        printf '  testing %-14s (%s) ... ' "$name" "$primary" >&2
        ms="$(dns_query_ms "$primary" github.com)"
        if [ -n "$ms" ]; then
            printf '%4d ms   OK\n' "$ms" >&2
            results+=("${ms}|${name}|${primary}|${secondary}")
        else
            printf '   FAIL  (no/late answer)\n' >&2
        fi
    done

    [ "${#results[@]}" -eq 0 ] && { echo; err "No Iranian DNS answered — leaving DNS unchanged."; return 1; }
    printf '%s\n' "${results[@]}" | sort -t'|' -k1,1n
}

# git config --system writes to /etc/gitconfig (or $GIT_CONFIG_DIR/etc
# config when sandboxed). Use env to redirect for tests.
run_git_config() {
    if [ -n "${VPSSEC_GITCONFIG:-}" ]; then
        GIT_CONFIG_DIR="$(dirname "$VPSSEC_GITCONFIG")" git config --file "$VPSSEC_GITCONFIG" "$@"
    else
        git config --system "$@"
    fi
}

# ---------- apply ----------

apply_mirror() {
    local name="$1" base="$2"
    info "Installing mirror '$name' system-wide (git insteadOf)..."
    run_git_config --replace-all "url.${base}.insteadof" "https://github.com/"
    MIRROR_NAME="$name" MIRROR_BASE="$base"
    save_mirror_conf
    log_mirror "mirror applied: $name ($base)"
    ok "All github.com git traffic now goes through $name"
    ok "  (git clone / pull / fetch / vpssec update — automatically)"
}

apply_dns() {
    local name="$1" primary="$2" secondary="$3"
    info "Switching server DNS to $name ($primary, $secondary)..."
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl is-active systemd-resolved 2>/dev/null | grep -qx active; then
        mkdir -p "$RESOLVED_CONF_D"
        printf '# vps-security — fastest Iranian DNS\n[Resolve]\nDNS=%s %s\nDomains=~.\n' \
            "$primary" "$secondary" > "$RESOLVED_CONF_D/vpssec-dns.conf"
        systemctl restart systemd-resolved 2>/dev/null || true
    else
        [ -f "$RESOLV_CONF" ] && [ ! -f "$RESOLV_CONF.vpssec.bak" ] \
            && cp "$RESOLV_CONF" "$RESOLV_CONF.vpssec.bak"
        printf 'nameserver %s\nnameserver %s\n' "$primary" "$secondary" > "$RESOLV_CONF"
    fi
    DNS_NAME="$name" DNS_PRIMARY="$primary" DNS_SECONDARY="$secondary"
    save_mirror_conf
    log_mirror "dns applied: $name ($primary, $secondary)"
    ok "Server DNS is now $name."
    if getent hosts github.com >/dev/null 2>&1; then
        ok "Verification: github.com resolves from this server."
    else
        warn "Verification could not resolve github.com — check connectivity."
    fi
}

reset_all() {
    load_mirror_conf
    info "Undoing mirror & DNS changes..."
    if [ -n "${MIRROR_BASE:-}" ]; then
        run_git_config --unset-all "url.${MIRROR_BASE}.insteadof" 2>/dev/null || true
    fi
    if [ -f "$RESOLVED_CONF_D/vpssec-dns.conf" ]; then
        rm -f "$RESOLVED_CONF_D/vpssec-dns.conf"
        systemctl restart systemd-resolved 2>/dev/null || true
    fi
    if [ -f "$RESOLV_CONF.vpssec.bak" ]; then
        cp "$RESOLV_CONF.vpssec.bak" "$RESOLV_CONF"
        rm -f "$RESOLV_CONF.vpssec.bak"
    fi
    rm -f "$MIRROR_CONF"
    log_mirror "reset: mirror + DNS restored"
    ok "Mirror rewrite removed and previous DNS restored."
}

mirror_status() {
    load_mirror_conf
    echo "=== Iranian mirror & DNS ==="
    if [ -n "${MIRROR_NAME:-}" ]; then
        echo "Git mirror    : $MIRROR_NAME ($MIRROR_BASE)"
    else
        echo "Git mirror    : not configured (direct github.com)"
    fi
    if [ -n "${DNS_NAME:-}" ]; then
        echo "Server DNS    : $DNS_NAME ($DNS_PRIMARY, $DNS_SECONDARY)"
    else
        echo "Server DNS    : system default"
    fi
    [ -f "$MIRROR_LOG" ] && { echo "History:"; tail -n 5 "$MIRROR_LOG" | sed 's/^/  /'; }
    return 0
}

# Full flow: test everything, install the fastest of each
apply_best() {
    echo "This measures REAL GitHub access speed from this server."
    echo
    local mirror_winner dns_winner
    mirror_winner="$(test_mirrors | grep -E '^[0-9]+\|' | head -1)" || true
    [ -z "$mirror_winner" ] && return 1
    local m_ms m_name m_base
    IFS='|' read -r m_ms m_name m_base <<< "$mirror_winner"
    echo
    ok "Fastest mirror: $m_name (${m_ms} ms)"
    apply_mirror "$m_name" "$m_base"

    echo
    dns_winner="$(test_dns | grep -E '^[0-9]+\|' | head -1)" || true
    if [ -z "$dns_winner" ]; then
        warn "DNS unchanged (no Iranian DNS reachable)."
        return 0
    fi
    local d_ms d_name d_p d_s
    IFS='|' read -r d_ms d_name d_p d_s <<< "$dns_winner"
    echo
    ok "Fastest DNS: $d_name (${d_ms} ms)"
    if mirror_confirm "Apply DNS $d_name to the whole server? [Y/n] "; then
        apply_dns "$d_name" "$d_p" "$d_s"
    else
        info "DNS left unchanged."
    fi
    return 0
}

case "${1:-}" in
    --test)   need_root; test_mirrors >/dev/null 2>&1; test_dns >/dev/null 2>&1; true ;;
    --best)   need_root; apply_best ;;
    --reset)  need_root; reset_all ;;
    --status) mirror_status ;;
    *) die "usage: mirror.sh (--best|--test|--reset|--status)" ;;
esac
