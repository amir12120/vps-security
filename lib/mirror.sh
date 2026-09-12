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
#   3. Tests IRANIAN PUBLIC DNS servers — a wide crowd-sourced
#      list of Iranian ISP/DCI resolvers plus the well-known
#      providers — by timing real github.com lookups. The fastest
#      is applied server-wide (systemd-resolved drop-in, or plain
#      /etc/resolv.conf).
#   4. Tests APT PACKAGE MIRRORS by measuring the real download
#      speed of dists/<codename>/InRelease, then writes the winner
#      into sources.list or the deb822 ubuntu.sources. A backup is
#      taken first and restored automatically if `apt-get update`
#      fails, so a bad mirror can never leave apt broken.
#   5. Can undo everything (`--reset`): removes the insteadOf
#      rewrite and restores the previous DNS + APT configuration.
#
# Choices are persisted in /etc/vps-security/mirror.conf.
#
# Env overrides (sandbox/testing):
#   VPSSEC_GITCONFIG        system gitconfig path (default /etc/gitconfig)
#   VPSSEC_RESOLVED_CONF_D  resolved drop-in dir (default /etc/systemd/resolved.conf.d)
#   VPSSEC_RESOLV_CONF      resolv.conf path (default /etc/resolv.conf)
#   VPSSEC_APT_SOURCES_LIST apt sources.list path (default /etc/apt/sources.list)
#   VPSSEC_APT_SOURCES_D    apt sources.list.d dir (default /etc/apt/sources.list.d)
#   VPSSEC_APT_BACKUP_DIR   apt backup dir (default /root/vpssec-apt-backup)
#   VPSSEC_APT_CODENAME     override the detected Ubuntu codename
#   VPSSEC_APT_SKIP_UPDATE  set to 1 to skip `apt-get update`
#   VPSSEC_DNS_TOOL         force the lookup tool (dig|nslookup|none)
#   MIRROR_INSTALL_DEPS     set to 0 to never apt-install dnsutils
#   MIRROR_PROBE_REPO       repo used for timing probes
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

MIRROR_CONF="$VPSSEC_CONF_DIR/mirror.conf"
MIRROR_LOG="$VPSSEC_STATE_DIR/mirror.log"
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

# Extra Iranian resolvers (primary|secondary|name).
# Crowd-sourced from the Iranian community (the list IranDNSFinder ships
# with). Many of these are ISP/DCI resolvers that are only reachable from
# inside Iran, so they are tested but never installed blindly. Entries with
# no known brand keep an empty name and are shown by their IP.
DNS_EXTRA=(
    "217.218.155.155||"
    "217.218.127.127||"
    "217.219.132.88||"
    "2.189.44.44||"
    "194.60.210.66||"
    "2.188.21.130|2.188.21.131|"
    "2.188.21.132||"
    "85.185.85.6||"
    "31.24.200.4|31.24.234.37|"
    "185.161.112.38||"
    "80.191.209.105||"
    "2.185.239.138||"
    "194.36.174.1||"
    "185.53.143.3|185.20.163.4|"
    "185.20.163.2||"
    "5.145.112.39||"
    "213.176.123.5||"
    "194.225.152.10||"
    "46.224.1.42||"
)

# ------------------------------------------------------------
# APT package mirrors — Iranian first, then well-known international
# fallbacks. Speed is measured by downloading the small-but-always-present
# dists/<codename>/InRelease file (a real repository round-trip, not a ping).
# ------------------------------------------------------------
APT_MIRROR_LIST=(
    "https://ubuntu.pishgaman.net/ubuntu"
    "http://mirror.aminidc.com/ubuntu"
    "https://ubuntu.pars.host"
    "https://ir.ubuntu.sindad.cloud/ubuntu"
    "https://ubuntu.shatel.ir/ubuntu"
    "https://ubuntu.mobinhost.com/ubuntu"
    "https://mirror.iranserver.com/ubuntu"
    "https://mirror.arvancloud.ir/ubuntu"
    "https://ubuntu.parsvds.com/ubuntu"
    "http://ir.archive.ubuntu.com/ubuntu"
    "https://archive.ubuntu.com/ubuntu"
    "https://mirror.leaseweb.com/ubuntu"
    "https://ftp.fau.de/ubuntu"
    "https://mirror.kumi.systems/ubuntu"
)

APT_SOURCES_LIST="${VPSSEC_APT_SOURCES_LIST:-/etc/apt/sources.list}"
APT_SOURCES_D="${VPSSEC_APT_SOURCES_D:-/etc/apt/sources.list.d}"
APT_BACKUP_DIR="${VPSSEC_APT_BACKUP_DIR:-/root/vpssec-apt-backup}"
APT_SKIP_UPDATE="${VPSSEC_APT_SKIP_UPDATE:-0}"

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
    MIRROR_NAME="" MIRROR_BASE="" DNS_NAME="" DNS_PRIMARY="" DNS_SECONDARY="" APT_MIRROR=""
    # shellcheck disable=SC1090  # config file path is dynamic
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
APT_MIRROR=${APT_MIRROR:-}
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

# Which resolver lookup tool do we have?  Both come from the same 'dnsutils'
# package. dig reports a precise query time; nslookup only lets us time the
# whole call, so it is the fallback.
dns_lookup_tool() {
    if [ -n "${VPSSEC_DNS_TOOL:-}" ]; then
        [ "$VPSSEC_DNS_TOOL" = "none" ] && return 1
        printf '%s\n' "$VPSSEC_DNS_TOOL"
        return 0
    fi
    command -v dig >/dev/null 2>&1 && { printf 'dig\n'; return 0; }
    command -v nslookup >/dev/null 2>&1 && { printf 'nslookup\n'; return 0; }
    return 1
}

# Install a lookup tool when one is missing. NEVER called from the read-only
# --test paths, and only when we are root with apt available.
ensure_dns_tool() {
    dns_lookup_tool >/dev/null 2>&1 && return 0
    [ "${MIRROR_INSTALL_DEPS:-1}" = "1" ] || return 1
    command -v apt-get >/dev/null 2>&1 || return 1
    [ "$(id -u 2>/dev/null)" = "0" ] || return 1
    info "Installing dnsutils (dig/nslookup) for the DNS speed test..."
    apt-get install -y dnsutils >/dev/null 2>&1 || true
    dns_lookup_tool >/dev/null 2>&1
}

dns_query_ms() {
    local ns="$1" host="$2" out tool t0 t1
    tool="$(dns_lookup_tool)" || return 1
    if [ "$tool" = "dig" ]; then
        out="$(dig "@$ns" "$host" +tries=1 +time=3 +noall +comments +answer 2>/dev/null)" || return 1
        echo "$out" | grep -q 'status: NOERROR' || return 1
        echo "$out" | grep -qE '^[^;].*\sA\s' || return 1
        echo "$out" | awk '/Query time:/ {print $4; exit}'
        return 0
    fi
    # nslookup fallback — time the call, trusting its exit status for success
    t0="$(now_ms)"
    out="$(nslookup -timeout=3 "$host" "$ns" 2>/dev/null)" || return 1
    t1="$(now_ms)"
    case "$t0$t1" in *[!0-9]*) return 1 ;; esac
    printf '%s\n' "$((t1 - t0))"
}

# Emits the deduped candidate list as "primary|secondary|name" (name falls
# back to the primary IP when the provider has no known brand).
dns_candidates() {
    local entry primary rest secondary name seen=" "
    for entry in "${DNS_LIST[@]}" "${DNS_EXTRA[@]}"; do
        primary="${entry%%|*}"; rest="${entry#*|}"
        secondary="${rest%%|*}"; name="${rest#*|}"
        [ -n "$primary" ] || continue
        case "$seen" in *" $primary "*) continue ;; esac
        seen="$seen$primary "
        [ -n "$name" ] || name="$primary"
        printf '%s|%s|%s\n' "$primary" "$secondary" "$name"
    done
}

# Times every DNS against github.com; prints "ms|name|primary|secondary" best-first
test_dns() {
    local primary secondary name ms
    ensure_dns_tool >/dev/null 2>&1 || true
    if ! dns_lookup_tool >/dev/null 2>&1; then
        # Both messages go to stderr: the read-only --test paths discard stdout,
        # and a missing-tool hint is useless if it gets thrown away with it.
        err "No DNS lookup tool found (need dig or nslookup)."
        printf '%b\n' "${YELLOW}[!]${RESET} Install it with:  sudo apt-get install -y dnsutils" >&2
        return 1
    fi
    echo >&2
    echo "=== Iranian DNS speed test (criterion: github.com resolution time) ===" >&2
    echo >&2
    local results=()
    while IFS='|' read -r primary secondary name; do
        printf '  testing %-18s (%s) ... ' "$name" "$primary" >&2
        ms="$(dns_query_ms "$primary" github.com)"
        if [ -n "$ms" ]; then
            printf '%4d ms   OK\n' "$ms" >&2
            results+=("${ms}|${name}|${primary}|${secondary}")
        else
            printf '   FAIL  (no/late answer)\n' >&2
        fi
    done < <(dns_candidates)

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
    local dns_pair="$primary"
    [ -n "$secondary" ] && dns_pair="$primary $secondary"
    info "Switching server DNS to $name ($dns_pair)..."
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl is-active systemd-resolved 2>/dev/null | grep -qx active; then
        mkdir -p "$RESOLVED_CONF_D"
        printf '# vps-security — fastest Iranian DNS\n[Resolve]\nDNS=%s\nDomains=~.\n' \
            "$dns_pair" > "$RESOLVED_CONF_D/vpssec-dns.conf"
        systemctl restart systemd-resolved 2>/dev/null || true
    else
        [ -f "$RESOLV_CONF" ] && [ ! -f "$RESOLV_CONF.vpssec.bak" ] \
            && cp "$RESOLV_CONF" "$RESOLV_CONF.vpssec.bak"
        {
            printf 'nameserver %s\n' "$primary"
            [ -n "$secondary" ] && printf 'nameserver %s\n' "$secondary"
        } > "$RESOLV_CONF"
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

# ---------- APT package mirror ----------

# Ubuntu/Debian codename (jammy, noble, bookworm…) — used to build the
# InRelease probe URL. Overridable so tests never touch the real system.
apt_codename() {
    if [ -n "${VPSSEC_APT_CODENAME:-}" ]; then
        printf '%s\n' "$VPSSEC_APT_CODENAME"; return 0
    fi
    local cn=""
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091  # os-release path is fixed at runtime
        cn="$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_CODENAME:-}")"
    fi
    [ -n "$cn" ] || cn="$(lsb_release -sc 2>/dev/null || true)"
    printf '%s\n' "$cn"
}

# apt_mirror_speed <mirror> <codename> -> KB/s on stdout, nothing on failure
apt_mirror_speed() {
    local mirror="$1" codename="$2" out
    out="$(curl -o /dev/null -fsSL --max-time 20 --connect-timeout 6 \
        -w '%{http_code} %{speed_download}' "$mirror/dists/$codename/InRelease" 2>/dev/null)" || return 1
    [ "${out%% *}" = "200" ] || return 1
    awk -v b="${out#* }" 'BEGIN { printf "%.1f", b / 1024 }'
}

# Which apt config file are we rewriting?  deb822 (Ubuntu 24.04+) or legacy.
apt_config_file() {
    if [ -f "$APT_SOURCES_D/ubuntu.sources" ]; then
        printf '%s\n' "$APT_SOURCES_D/ubuntu.sources"
    elif [ -f "$APT_SOURCES_LIST" ]; then
        printf '%s\n' "$APT_SOURCES_LIST"
    fi
}

# Times every apt mirror; prints "kb|mirror" fastest-first
test_apt_mirrors() {
    local codename entry kb
    codename="$(apt_codename)"
    if [ -z "$codename" ]; then
        err "Cannot detect the Ubuntu/Debian codename — apt mirror test skipped."
        return 1
    fi
    echo "=== APT mirror speed test (criterion: dists/$codename/InRelease download) ===" >&2
    echo >&2
    local results=()
    for entry in "${APT_MIRROR_LIST[@]}"; do
        printf '  testing %-46s ... ' "$entry" >&2
        kb="$(apt_mirror_speed "$entry" "$codename")"
        if [ -n "$kb" ]; then
            printf '%9s KB/s   OK\n' "$kb" >&2
            results+=("${kb}|${entry}")
        else
            printf '     FAIL  (unreachable)\n' >&2
        fi
    done
    [ "${#results[@]}" -eq 0 ] && { echo >&2; err "No apt mirror answered — apt sources left unchanged."; return 1; }
    printf '%s\n' "${results[@]}" | sort -t'|' -k1,1nr
}

# Snapshots the current apt configuration.
#   $APT_BACKUP_DIR/<timestamp>  the immediately-previous state (rollback on failure)
#   $APT_BACKUP_DIR/pristine     the FIRST state we ever saw — never overwritten,
#                                so `--reset` always returns to the distro default
#                                even after several applies.
backup_apt_config() {
    local stamp
    stamp="$(date +%Y%m%d-%H%M%S)"
    APT_BACKUP_LAST="$APT_BACKUP_DIR/$stamp"
    mkdir -p "$APT_BACKUP_LAST"
    [ -f "$APT_SOURCES_LIST" ] && cp -a "$APT_SOURCES_LIST" "$APT_BACKUP_LAST/"
    [ -d "$APT_SOURCES_D" ] && cp -a "$APT_SOURCES_D" "$APT_BACKUP_LAST/sources.list.d"
    printf '%s\n' "$APT_BACKUP_LAST" > "$APT_BACKUP_DIR/LATEST"
    if [ ! -d "$APT_BACKUP_DIR/pristine" ]; then
        cp -a "$APT_BACKUP_LAST" "$APT_BACKUP_DIR/pristine"
    fi
    return 0
}

# restore_apt_config [dir] — with no argument prefers the pristine snapshot
# (that is what --reset must return to), falling back to the latest one.
# The pristine snapshot uses a FIXED path (no pointer file) so it cannot
# collide with anything on a case-insensitive filesystem.
restore_apt_config() {
    local dir="$1"
    if [ -z "$dir" ] && [ -d "$APT_BACKUP_DIR/pristine" ]; then
        dir="$APT_BACKUP_DIR/pristine"
    fi
    if [ -z "$dir" ] && [ -f "$APT_BACKUP_DIR/LATEST" ]; then
        dir="$(cat "$APT_BACKUP_DIR/LATEST" 2>/dev/null)"
    fi
    [ -n "$dir" ] && [ -d "$dir" ] || return 1
    [ -f "$dir/sources.list" ] && cp -a "$dir/sources.list" "$APT_SOURCES_LIST"
    if [ -d "$dir/sources.list.d" ]; then
        rm -rf "$APT_SOURCES_D"
        mkdir -p "$(dirname "$APT_SOURCES_D")"
        cp -a "$dir/sources.list.d" "$APT_SOURCES_D"
    fi
    return 0
}

apply_apt_mirror() {
    local mirror="$1" cfg base
    cfg="$(apt_config_file)"
    if [ -z "$cfg" ]; then
        err "No apt repository file found ($APT_SOURCES_LIST or $APT_SOURCES_D/ubuntu.sources)."
        return 1
    fi
    base="$(basename "$cfg")"
    info "Backing up apt configuration to $APT_BACKUP_DIR ..."
    backup_apt_config
    local backup="$APT_BACKUP_LAST"
    info "Pointing $base at $mirror ..."
    if [ "$base" = "ubuntu.sources" ]; then
        sed -i -E "s|^URIs:[[:space:]].*|URIs: ${mirror}|" "$cfg"
    else
        sed -i -E "s|https?://[^[:space:]]*ubuntu[^[:space:]]*|${mirror}|g" "$cfg"
    fi
    if [ "$APT_SKIP_UPDATE" != "1" ]; then
        info "Running apt-get update to verify the new mirror ..."
        if ! command -v apt-get >/dev/null 2>&1 || ! apt-get update >/dev/null 2>&1; then
            warn "apt-get update failed with this mirror — restoring the previous configuration."
            restore_apt_config "$backup"
            log_mirror "apt mirror rejected (apt update failed): $mirror"
            return 1
        fi
    fi
    APT_MIRROR="$mirror"
    save_mirror_conf
    log_mirror "apt mirror applied: $mirror"
    ok "APT packages now come from $mirror"
    ok "  (backup kept at $backup — undo with: vpssec mirror reset)"
    return 0
}

# Full apt flow: test all mirrors, then apply the fastest after confirmation
apt_best() {
    echo "This measures the REAL download speed of the apt repository index."
    echo
    local winner
    winner="$(test_apt_mirrors | grep -E '^[0-9.]+\|' | head -1)" || true
    [ -z "$winner" ] && return 1
    local kb mirror
    IFS='|' read -r kb mirror <<< "$winner"
    echo
    ok "Fastest apt mirror: $mirror (${kb} KB/s)"
    if mirror_confirm "Switch this server's apt sources to that mirror? [Y/n] "; then
        apply_apt_mirror "$mirror"
    else
        info "apt sources left unchanged."
    fi
    return 0
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
    if [ -n "${APT_MIRROR:-}" ] || [ -d "$APT_BACKUP_DIR/pristine" ]; then
        if restore_apt_config; then
            ok "apt sources restored to the distribution default."
            log_mirror "reset: apt sources restored"
        fi
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
        echo "Server DNS    : $DNS_NAME ($DNS_PRIMARY${DNS_SECONDARY:+, $DNS_SECONDARY})"
    else
        echo "Server DNS    : system default"
    fi
    if [ -n "${APT_MIRROR:-}" ]; then
        echo "APT mirror    : $APT_MIRROR"
    else
        echo "APT mirror    : distribution default"
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
    # NOTE: stdout (the machine-readable result lines) is discarded here, but
    # stderr carries the human-readable speed tables — so "test only" really
    # shows the table instead of printing nothing.
    # read-only modes: never apt-install anything
    --test)     need_root; MIRROR_INSTALL_DEPS=0 test_mirrors >/dev/null; MIRROR_INSTALL_DEPS=0 test_dns >/dev/null; true ;;
    --apt-test) need_root; test_apt_mirrors >/dev/null; true ;;
    --best)     need_root; ensure_dns_tool >/dev/null 2>&1 || true; apply_best ;;
    --apt)      need_root; apt_best ;;
    --reset)    need_root; reset_all ;;
    --status)   mirror_status ;;
    *) die "usage: mirror.sh (--best|--test|--apt|--apt-test|--reset|--status)" ;;
esac
