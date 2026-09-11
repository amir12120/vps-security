#!/usr/bin/env bash
# ============================================================
# vps-security — GeoIP country firewall
#
# Lets the user whitelist ANY number of countries; every other
# country is blocked from reaching the server.
#
# Implementation:
#   - Country CIDR lists downloaded from IPFire's location service
#     (https://www.ipfire.org/location  — free, no API key, updated
#     daily) into /var/lib/vps-security/geo/
#   - An ipset (hash:net) per feature state, referenced by ufw
#     before.rules rules: allow from <set> , then DROP everything
#     else on all ports.
#   - BYPASS_IPS in geo.conf are never blocked (your own IPs).
#
# Usage:
#   geoip.sh --add <XX,YY,...>      add countries (ISO 2-letter codes)
#   geoip.sh --remove <XX,...>      remove countries
#   geoip.sh --list                 show configured countries + set size
#   geoip.sh --enable               apply the firewall rules
#   geoip.sh --disable              remove all geo rules
#   geoip.sh --bypass add|remove|list [ip]
#   geoip.sh --refresh              re-download CIDR lists
#   geoip.sh --health               exit 0 if enabled
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

GEO_CONF="$VPSSEC_CONF_DIR/geo.conf"
GEO_DIR="$VPSSEC_STATE_DIR/geo"
GEO_LOG="$VPSSEC_STATE_DIR/geo.log"
IPSET_NAME="vpssec_geo_allow"
GEO_URL_BASE="${GEO_URL_BASE:-https://www.ipfire.org/geoip/country}"

BEFORE_RULES="$UFW_DIR/before.rules"
MARK_BEGIN="# --- vps-security geoip BEGIN ---"
MARK_END="# --- vps-security geoip END ---"

cmd_ipset()     { ipset "$@"; }
cmd_ufw()       { ufw "$@"; }
cmd_systemctl() { systemctl "$@"; }
cmd_curl()      { curl -fsSL --max-time 120 "$@"; }

have_ipset() { command -v ipset >/dev/null 2>&1; }

# ---------- conf ----------

geo_enabled() { [ -f "$GEO_CONF" ] && grep -q '^GEO_ENABLED=1$' "$GEO_CONF" 2>/dev/null; }

load_geo_conf() {
    GEO_COUNTRIES=""
    GEO_BYPASS=""
    [ -f "$GEO_CONF" ] && . "$GEO_CONF" 2>/dev/null
    return 0
}

save_geo_conf() {
    ensure_dirs
    cat > "$GEO_CONF" <<EOF
GEO_ENABLED=${GEO_ENABLED:-0}
GEO_COUNTRIES=${GEO_COUNTRIES:-}
GEO_BYPASS=${GEO_BYPASS:-}
EOF
    chmod 600 "$GEO_CONF"
}

valid_cc() { printf '%s' "$1" | grep -qE '^[A-Za-z]{2}$'; }

norm_cc() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

# ---------- country name resolution ----------
# Lets users type full country names (English or Persian), ISO alpha-3
# codes (USA), or unique name prefixes instead of remembering 2-letter
# ISO codes. Table: CODE|A3|english|alias1|alias2... (aliases may be
# English or Persian; everything space-stripped, English lowercase).
CC_TABLE=(
"IR|IRN|iran|ایران"
"DE|DEU|germany|آلمان"
"US|USA|unitedstates|america|usa|امریکا|آمریکا"
"GB|GBR|unitedkingdom|uk|britain|england|انگلستان|بریتانیا"
"TR|TUR|turkey|turkiye|ترکیه"
"AE|ARE|unitedarabemirates|uae|dubai|امارات"
"NL|NLD|netherlands|holland|هلند"
"FR|FRA|france|فرانسه"
"CA|CAN|canada|کانادا"
"RU|RUS|russia|روسیه"
"CN|CHN|china|چین"
"JP|JPN|japan|ژاپن"
"KR|KOR|southkorea|korea|کره"
"IN|IND|india|هند"
"IQ|IRQ|iraq|عراق"
"AF|AFG|afghanistan|افغانستان"
"PK|PAK|pakistan|پاکستان"
"AZ|AZE|azerbaijan|آذربایجان"
"AM|ARM|armenia|ارمنستان"
"IT|ITA|italy|ایتالیا"
"ES|ESP|spain|اسپانیا"
"SE|SWE|sweden|سوئد"
"NO|NOR|norway|نروژ"
"FI|FIN|finland|فنلاند"
"DK|DNK|denmark|دانمارک"
"CH|CHE|switzerland|سوئیس|سویس"
"AT|AUT|austria|اتریش"
"BE|BEL|belgium|بلژیک"
"PL|POL|poland|لهستان"
"CZ|CZE|czechia|czechrepublic|چک"
"RO|ROU|romania|رومانی"
"GR|GRC|greece|یونان"
"SA|SAU|saudiarabia|arabia|عربستان"
"QA|QAT|qatar|قطر"
"KW|KWT|kuwait|کویت"
"OM|OMN|oman|عمان"
"BH|BHR|bahrain|بحرین"
"JO|JOR|jordan|اردن"
"LB|LBN|lebanon|لبنان"
"EG|EGY|egypt|مصر"
"MY|MYS|malaysia|مالزی"
"ID|IDN|indonesia|اندونزی"
"AU|AUS|australia|استرالیا|اوسترالیا"
"UA|UKR|ukraine|اوکراین"
"KZ|KAZ|kazakhstan|قزاقستان"
"GE|GEO|georgia|گرجستان"
"AR|ARG|argentina|آرژانتین"
"BR|BRA|brazil|برزیل"
)

# resolve_cc <token> -> prints ISO alpha-2 code, or fails when unknown
# Accepts: 2-letter code, alpha-3, exact English/Persian name, or a
# UNIQUE prefix of the English name (e.g. "German" -> DE; "united" is
# ambiguous and therefore rejected).
resolve_cc() {
    local in cc key entry code rest field found cnt
    in="$(printf '%s' "$1" | tr -d '[:space:]')"
    [ -z "$in" ] && return 1
    cc="$(norm_cc "$in")"
    if valid_cc "$cc"; then printf '%s\n' "$cc"; return 0; fi
    key="$(printf '%s' "$in" | tr '[:upper:]' '[:lower:]')"
    # pass 1: exact match on alpha-3 / English name / any alias
    for entry in "${CC_TABLE[@]}"; do
        code="${entry%%|*}"; rest="${entry#*|}"
        if [ "$key" = "$(printf '%s' "${rest%%|*}" | tr '[:upper:]' '[:lower:]')" ]; then
            printf '%s\n' "$code"; return 0
        fi
        rest="${rest#*|}"
        local IFS='|'
        for field in $rest; do
            if [ "$key" = "$(printf '%s' "$field" | tr '[:upper:]' '[:lower:]')" ]; then
                printf '%s\n' "$code"; return 0
            fi
        done
    done
    # pass 2: unique prefix of the English primary name
    found=""; cnt=0
    for entry in "${CC_TABLE[@]}"; do
        code="${entry%%|*}"; rest="${entry#*|}"; rest="${rest#*|}"
        case "${rest%%|*}" in
            "$key"*) found="$code"; cnt=$((cnt + 1)) ;;
        esac
    done
    if [ "$cnt" -eq 1 ]; then printf '%s\n' "$found"; return 0; fi
    return 1
}

# ---------- country list management ----------

geo_add_countries() {
    local input="$1" added=() cc resolved
    load_geo_conf
    IFS=',' read -ra ccs <<< "$input"
    for cc in "${ccs[@]:-}"; do
        [ -z "$(printf '%s' "$cc" | tr -d '[:space:]')" ] && continue
        if ! resolved="$(resolve_cc "$cc")"; then
            warn "'$cc' is not a valid country code or name (e.g. IR, DE, Iran, Germany, ایران)."
            continue
        fi
        cc="$resolved"
        case ",${GEO_COUNTRIES}," in
            *",$cc,"*) info "$cc already allowed." ;;
            *)
                GEO_COUNTRIES="${GEO_COUNTRIES:+$GEO_COUNTRIES,}$cc"
                added+=("$cc")
                ;;
        esac
    done
    if [ "${#added[@]}" -gt 0 ]; then
        save_geo_conf
        ok "Countries now allowed: $(echo "$GEO_COUNTRIES" | tr ',' ' ')"
        info "Run --enable (or the CLI Geo menu) to download lists and apply."
        printf '%s ADD %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${added[*]}" >> "$GEO_LOG"
        return 0
    fi
    return 0
}

geo_remove_countries() {
    local input="$1" out="" removed=() cc resolved
    load_geo_conf
    IFS=',' read -ra ccs <<< "$input"
    for cc in "${ccs[@]:-}"; do
        [ -z "$(printf '%s' "$cc" | tr -d '[:space:]')" ] && continue
        if ! resolved="$(resolve_cc "$cc")"; then
            warn "'$cc' is not a valid country code or name — skipped."
            continue
        fi
        cc="$resolved"
        case ",${GEO_COUNTRIES}," in
            *",$cc,"*)
                removed+=("$cc")
                ;;
        esac
    done
    # rebuild list without removed
    if [ -n "$GEO_COUNTRIES" ]; then
        IFS=',' read -ra cur <<< "$GEO_COUNTRIES"
        for cc in "${cur[@]}"; do
            local keep=1 r
            for r in "${removed[@]:-}"; do
                [ "$cc" = "$r" ] && keep=0
            done
            [ "$keep" -eq 1 ] && out="${out:+$out,}$cc"
        done
    fi
    GEO_COUNTRIES="$out"
    save_geo_conf
    [ "${#removed[@]}" -gt 0 ] && printf '%s REMOVE %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${removed[*]}" >> "$GEO_LOG"
    if [ -n "$GEO_COUNTRIES" ]; then
        ok "Countries now allowed: $(echo "$GEO_COUNTRIES" | tr ',' ' ')"
    else
        # SAFETY: the last country was removed. If filtering is still
        # active, disable it completely RIGHT NOW (rules, timer, ipset)
        # so the server stays reachable from everywhere. Even bypass IPs
        # must not keep a world-DROP alive with zero allowed countries.
        if geo_enabled; then
            geo_disable
            ok "Last country removed — geo filter DISABLED automatically."
            ok "The server is open to ALL countries again."
        else
            ok "No countries configured — geo filtering is effectively off."
        fi
    fi
    return 0
}

geo_list() {
    load_geo_conf
    echo "=== GeoIP country filter ==="
    if geo_enabled; then echo "State: ENABLED"; else echo "State: disabled"; fi
    if [ -n "$GEO_COUNTRIES" ]; then
        echo "Allowed countries: $(echo "$GEO_COUNTRIES" | tr ',' ' ')"
        local cc total=0 lines
        for cc in $(echo "$GEO_COUNTRIES" | tr ',' ' '); do
            [ -f "$GEO_DIR/$cc.cidr" ] || { echo "  $cc: (list not downloaded)"; continue; }
            lines="$(wc -l < "$GEO_DIR/$cc.cidr" | tr -d ' ')"
            total=$((total + lines))
            printf '  %s: %s ranges\n' "$cc" "$lines"
        done
        echo "Total ranges: $total"
    else
        echo "Allowed countries: (none configured)"
    fi
    echo "Bypass IPs: ${GEO_BYPASS:-(none)}"
    return 0
}

# ---------- download ----------

geo_download() {
    ensure_dirs
    mkdir -p "$GEO_DIR"
    load_geo_conf
    [ -z "$GEO_COUNTRIES" ] && { warn "No countries configured."; return 1; }
    if ! command -v curl >/dev/null 2>&1; then
        err "curl is required to download country lists."
        return 1
    fi
    local cc file url
    for cc in $(echo "$GEO_COUNTRIES" | tr ',' ' '); do
        file="$GEO_DIR/$cc.cidr"
        url="$GEO_URL_BASE/$cc.cidr"
        info "Downloading $cc ranges..."
        if cmd_curl "$url" -o "$file.tmp" 2>/dev/null && [ -s "$file.tmp" ]; then
            # keep only IPv4 CIDRs, one per line
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$file.tmp" > "$file" || true
            rm -f "$file.tmp"
            if [ -s "$file" ]; then
                ok "  $cc: $(wc -l < "$file" | tr -d ' ') ranges"
            else
                warn "  $cc: empty list (wrong code?)"
                rm -f "$file"
            fi
        else
            rm -f "$file.tmp"
            warn "  $cc: download failed (check internet access)"
        fi
    done
    return 0
}

# ---------- ipset ----------

geo_ipset_rebuild() {
    have_ipset || { err "ipset is not installed (apt-get install -y ipset)."; return 1; }
    ensure_dirs
    load_geo_conf
    cmd_ipset destroy "$IPSET_NAME" 2>/dev/null || true
    if ! cmd_ipset create "$IPSET_NAME" hash:net family inet -exist 2>/dev/null; then
        err "Cannot create ipset $IPSET_NAME."
        return 1
    fi
    local cc ip
    for cc in $(echo "${GEO_COUNTRIES:-}" | tr ',' ' '); do
        [ -f "$GEO_DIR/$cc.cidr" ] || continue
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            cmd_ipset add "$IPSET_NAME" "$ip" -exist 2>/dev/null || true
        done < "$GEO_DIR/$cc.cidr"
    done
    ok "ipset $IPSET_NAME populated ($(cmd_ipset list "$IPSET_NAME" 2>/dev/null | grep -c '^[0-9]' || echo '?') entries)."
    return 0
}

# ---------- before.rules block ----------

# ---------- safety invariant ----------
# The final-DROP rule must only ever be installed when the allow-set can
# actually contain addresses (at least one non-empty country list, or at
# least one bypass IP). Otherwise a config mistake or a failed download
# would DROP THE WHOLE WORLD including the administrator's SSH session.
geo_ruleset_is_safe() {
    load_geo_conf
    [ -n "${GEO_BYPASS:-}" ] && return 0
    local cc
    for cc in $(echo "${GEO_COUNTRIES:-}" | tr ',' ' '); do
        [ -s "$GEO_DIR/$cc.cidr" ] && return 0
    done
    return 1
}

geo_rules_text() {
    local bypass=() ip
    [ -n "$GEO_BYPASS" ] && IFS=',' read -ra bypass <<< "$GEO_BYPASS"
    cat <<EOF
$MARK_BEGIN
# geo filter: allow whitelisted countries, drop the rest
EOF
    for ip in "${bypass[@]:-}"; do
        [ -n "$ip" ] && echo "-A ufw-before-input -s $ip -j ACCEPT" || true
    done
    cat <<EOF
-A ufw-before-input -m set --match-set $IPSET_NAME src -j ACCEPT
-A ufw-before-input -j DROP
$MARK_END
EOF
}

geo_write_rules() {
    # SAFETY: never install a world-blocking ruleset with an empty allow-set
    if ! geo_ruleset_is_safe; then
        err "Refusing to enable geo blocking: no country ranges available and no bypass IPs."
        err "The firewall was NOT modified — access from everywhere stays open."
        return 1
    fi
    [ -f "$BEFORE_RULES" ] || { err "$BEFORE_RULES not found (is ufw installed?)"; return 1; }
    sed -i "/^${MARK_BEGIN}\$/,/^${MARK_END}\$/d" "$BEFORE_RULES"
    printf '\n%s\n' "$(geo_rules_text)" >> "$BEFORE_RULES"
    return 0
}

# Remove the geo rules block if present (used when the ruleset is unsafe)
geo_strip_if_unsafe() {
    if ! geo_ruleset_is_safe; then
        geo_remove_rules
        cmd_ipset destroy "$IPSET_NAME" 2>/dev/null || true
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -q active; then
            cmd_ufw reload >/dev/null 2>&1 || true
        fi
        printf '%s SAFETY allow-set empty — geo rules removed, server open to all\n' \
            "$(date '+%Y-%m-%d %H:%M:%S')" >> "$GEO_LOG"
        return 0
    fi
    return 1
}

geo_remove_rules() {
    [ -f "$BEFORE_RULES" ] || return 0
    sed -i "/^${MARK_BEGIN}\$/,/^${MARK_END}\$/d" "$BEFORE_RULES"
    return 0
}

# ---------- enable / disable ----------

geo_enable() {
    load_geo_conf
    # SAFETY: with no countries configured the filter must simply never be
    # enabled — the server stays reachable from anywhere in the world.
    if [ -z "${GEO_COUNTRIES:-}" ]; then
        warn "No countries configured — geo filtering is NOT enabled."
        info "The server remains accessible from ALL countries."
        info "Add countries first:  geoip.sh --add IR,DE   (or via the CLI Geo menu)."
        return 0
    fi
    ensure_dirs
    if ! have_ipset; then
        info "Installing ipset..."
        apt-get install -y ipset >/dev/null 2>&1 || true
    fi
    have_ipset || die "ipset is required but not installed (apt-get install -y ipset)."

    # ensure ipset present after reboot: install a restore service
    geo_download || true
    geo_ipset_rebuild || die "ipset rebuild failed."
    # SAFETY: if the downloads failed, every allow-set is empty. Never write
    # the world-DROP rule in that state.
    if ! geo_ruleset_is_safe; then
        geo_strip_if_unsafe || true
        err "Country lists are empty (download failed?) — geo filtering NOT enabled."
        err "The server remains accessible from ALL countries. Fix internet access and re-run --enable."
        return 1
    fi
    geo_write_rules || die "writing ufw rules failed."
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -q active; then
        cmd_ufw reload >/dev/null 2>&1 || true
    fi

    # persist ipset across reboots
    mkdir -p "$GEO_DIR"
    cat > "$VPSSEC_SYSTEMD_DIR/vps-security-geo.service" <<EOF
[Unit]
Description=vps-security GeoIP ipset restore
After=network.target
Before=ufw.service

[Service]
Type=oneshot
ExecStart=$SCRIPT_DIR/lib/geoip.sh --ipset-restore
RemainAfterExit=yes
EOF
    cat > "$VPSSEC_SYSTEMD_DIR/vps-security-geo.timer" <<EOF
[Unit]
Description=Weekly GeoIP list refresh

[Timer]
OnBootSec=5min
OnUnitActiveSec=7d
Unit=vps-security-geo.service

[Install]
WantedBy=timers.target
EOF
    cmd_systemctl daemon-reload
    cmd_systemctl enable --now vps-security-geo.timer

    GEO_ENABLED=1
    save_geo_conf
    printf '%s geo enabled (countries: %s)\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$GEO_COUNTRIES" >> "$GEO_LOG"
    ok "GeoIP filter ENABLED — only the configured countries can reach this server."
    warn "Make sure your own IP is allowed (it is, if it is in a whitelisted country) —"
    warn "otherwise add it with:  geoip.sh --bypass add <your-ip>"
}

geo_disable() {
    load_geo_conf
    geo_remove_rules
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -q active; then
        cmd_ufw reload >/dev/null 2>&1 || true
    fi
    cmd_systemctl disable --now vps-security-geo.timer 2>/dev/null || true
    rm -f "$VPSSEC_SYSTEMD_DIR"/vps-security-geo.{service,timer}
    cmd_systemctl daemon-reload
    cmd_ipset destroy "$IPSET_NAME" 2>/dev/null || true
    GEO_ENABLED=0
    save_geo_conf
    printf '%s geo disabled\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$GEO_LOG"
    ok "GeoIP filter disabled — all countries can reach the server again."
}

# ---------- bypass ----------

geo_bypass() {
    local op="$1" ip="${2:-}"
    load_geo_conf
    case "$op" in
        add)
            printf '%s' "$ip" | grep -qE '^[0-9a-fA-F.:]+(/[0-9]+)?$' || die "invalid IP: $ip"
            case ",${GEO_BYPASS}," in
                *",$ip,"*) info "already bypassed." ;;
                *)
                    GEO_BYPASS="${GEO_BYPASS:+$GEO_BYPASS,}$ip"
                    save_geo_conf
                    ok "IP $ip will never be geo-blocked."
                    if geo_enabled; then
                        geo_write_rules && cmd_ufw reload >/dev/null 2>&1 || true
                    fi
                    ;;
            esac
            ;;
        remove)
            local out="" b
            IFS=',' read -ra bs <<< "$GEO_BYPASS"
            for b in "${bs[@]:-}"; do
                [ "$b" = "$ip" ] || out="${out:+$out,}$b"
            done
            GEO_BYPASS="$out"
            save_geo_conf
            ok "IP $ip removed from bypass list."
            ;;
        list)
            echo "Bypass IPs: ${GEO_BYPASS:-(none)}"
            ;;
        *) die "usage: --bypass add|remove|list [ip]" ;;
    esac
}

# ---------- refresh (weekly timer) ----------

geo_refresh() {
    load_geo_conf
    geo_enabled || return 0
    info "Refreshing country lists..."
    geo_download || true
    # SAFETY: never leave a world-DROP active while the allow-set is empty
    # (e.g. all refresh downloads failed). Strip the geo rules instead so
    # the server stays reachable.
    geo_strip_if_unsafe || geo_ipset_rebuild || true
    return 0
}

case "${1:-}" in
    --add)    shift; need_root; geo_add_countries "${1:-}";;
    --remove) shift; need_root; geo_remove_countries "${1:-}";;
    --list)   geo_list ;;
    --enable) need_root; geo_enable ;;
    --disable) need_root; geo_disable ;;
    --bypass) shift; geo_bypass "${1:-}" "${2:-}" ;;
    --refresh) need_root; geo_refresh ;;
    --ipset-restore)
        # SAFETY at boot: if the on-disk config is unsafe (no countries /
        # empty lists / no bypass), remove any geo rules so the server is
        # never left blocked from the whole world after a reboot.
        if ! geo_ruleset_is_safe; then
            geo_strip_if_unsafe || true
            exit 0
        fi
        geo_ipset_rebuild || true
        geo_write_rules 2>/dev/null || true
        ;;
    --health) geo_enabled ;;
    *) die "usage: geoip.sh (--add <CC,..>|--remove <CC,..>|--list|--enable|--disable|--bypass|--refresh|--health)" ;;
esac
