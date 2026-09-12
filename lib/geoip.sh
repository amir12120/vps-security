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
# THIS IS AN ALLOW-LIST. The countries you add are the ONLY ones that may
# reach the server; every other country is dropped. It is NOT a list of
# countries to block.
#
# SSH can never be locked out permanently, even if the allow-list is wrong:
#   1. --enable refuses to run unless EVERY configured country has a
#      downloaded range list. Accepting a partial download used to allow
#      only whichever country happened to download — an instant lockout.
#   2. the IP you are connected from right now is added to the bypass list
#      automatically and checked against the ipset.
#   3. a confirmation window: unless you run --confirm within
#      GEO_CONFIRM_SECONDS (default 600) the filter removes itself and the
#      server re-opens. Losing SSH is therefore temporary, not fatal.
#   4. --panic removes the filter immediately, from any console.
#
# Usage:
#   geoip.sh --add <XX,YY,...>      add countries (ISO 2-letter codes)
#   geoip.sh --remove <XX,...>      remove countries
#   geoip.sh --list                 show configured countries + set size
#   geoip.sh --enable               apply the rules (starts the confirm window)
#   geoip.sh --confirm              keep the change (stops the auto re-open)
#   geoip.sh --panic                remove the filter right now (rescue)
#   geoip.sh --disable              remove all geo rules
#   geoip.sh --bypass add|remove|list [ip]
#   geoip.sh --refresh              re-download CIDR lists
#   geoip.sh --cc-name <CC>         print a country's English name (NL -> netherlands)
#   geoip.sh --health               exit 0 if enabled
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

GEO_CONF="$VPSSEC_CONF_DIR/geo.conf"
GEO_DIR="$VPSSEC_STATE_DIR/geo"
GEO_LOG="$VPSSEC_STATE_DIR/geo.log"
IPSET_NAME="vpssec_geo_allow"
GEO_URL_BASE="${GEO_URL_BASE:-https://www.ipfire.org/geoip/country}"

# Safety net: after a filter change the admin has this long to confirm it.
# If they never do (because they lost SSH), the filter removes itself.
GEO_CONFIRM_SECONDS="${GEO_CONFIRM_SECONDS:-600}"
GEO_PENDING="$VPSSEC_STATE_DIR/geo-pending"
GEO_GUARD_SERVICE="vps-security-geo-guard.service"
GEO_GUARD_TIMER="vps-security-geo-guard.timer"

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
"DE|DEU|germany|آلمان|deutschland"
"US|USA|unitedstates|america|usa|امریکا|آمریکا"
"GB|GBR|unitedkingdom|uk|britain|england|انگلستان|بریتانیا|انگلیس"
"TR|TUR|turkey|turkiye|ترکیه"
"AE|ARE|unitedarabemirates|uae|dubai|امارات|دبی"
"NL|NLD|netherlands|holland|هلند|nederland|nederlands"
"FR|FRA|france|فرانسه"
"CA|CAN|canada|کانادا"
"RU|RUS|russia|روسیه"
"CN|CHN|china|چین"
"JP|JPN|japan|ژاپن"
"KR|KOR|southkorea|korea|کره|کرهجنوبی"
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
"IE|IRL|ireland|ایرلند"
"IS|ISL|iceland|ایسلند"
"PT|PRT|portugal|پرتغال"
"LU|LUX|luxembourg|لوکزامبورگ"
"MT|MLT|malta|مالت"
"CY|CYP|cyprus|قبرس"
"HU|HUN|hungary|مجارستان"
"BG|BGR|bulgaria|بلغارستان"
"RS|SRB|serbia|صربستان"
"HR|HRV|croatia|کرواسی"
"SI|SVN|slovenia|اسلوونی"
"SK|SVK|slovakia|اسلواکی"
"LT|LTU|lithuania|لیتوانی"
"LV|LVA|latvia|لتونی"
"EE|EST|estonia|استونی"
"BY|BLR|belarus|بلاروس"
"MD|MDA|moldova|مولداوی"
"AL|ALB|albania|آلبانی"
"ME|MNE|montenegro|مونتهنگرو"
"MK|MKD|northmacedonia|macedonia|مقدونیه"
"BA|BIH|bosnia|bosniaandherzegovina|بوسنی"
"IL|ISR|israel|اسرائیل"
"PS|PSE|palestine|فلسطین"
"SY|SYR|syria|سوریه"
"YE|YEM|yemen|یمن"
"SD|SDN|sudan|سودان"
"LY|LBY|libya|لیبی"
"TN|TUN|tunisia|تونس"
"DZ|DZA|algeria|الجزایر"
"MA|MAR|morocco|مراکش|مغرب"
"NG|NGA|nigeria|نیجریه"
"KE|KEN|kenya|کنیا"
"ZA|ZAF|southafrica|افریقایجنوبی|آفریقایجنوبی"
"TZ|TZA|tanzania|تانزانیا"
"ET|ETH|ethiopia|اتیوپی"
"GH|GHA|ghana|غنا"
"UZ|UZB|uzbekistan|ازبکستان"
"TJ|TJK|tajikistan|تاجیکستان"
"TM|TKM|turkmenistan|ترکمنستان"
"KG|KGZ|kyrgyzstan|قرقیزستان"
"MN|MNG|mongolia|مغولستان"
"TH|THA|thailand|تایلند"
"VN|VNM|vietnam|ویتنام"
"PH|PHL|philippines|فیلیپین"
"SG|SGP|singapore|سنگاپور"
"BD|BGD|bangladesh|بنگلادش"
"LK|LKA|srilanka|سریلانکا"
"NP|NPL|nepal|نپال"
"MM|MMR|myanmar|burma|میانمار"
"KH|KHM|cambodia|کامبوج"
"TW|TWN|taiwan|تایوان"
"HK|HKG|hongkong|هنگکنگ"
"NZ|NZL|newzealand|نیوزیلند"
"MX|MEX|mexico|مکزیک"
"CL|CHL|chile|شیلی"
"CO|COL|colombia|کلمبیا"
"PE|PER|peru|پرو"
"VE|VEN|venezuela|ونزوئلا"
"EC|ECU|ecuador|اکوادور"
"UY|URY|uruguay|اروگوئه"
"PY|PRY|paraguay|پاراگوئه"
"BO|BOL|bolivia|بولیوی"
"CU|CUB|cuba|کوبا"
"CR|CRI|costarica|کاستاریکا"
"PA|PAN|panama|پاناما"
"DO|DOM|dominicanrepublic|دومینیکن"
"GT|GTM|guatemala|گواتمالا"
"HN|HND|honduras|هندوراس"
"SV|SLV|elsalvador|السالوادور"
"NI|NIC|nicaragua|نیکاراگوئه"
"PR|PRI|puertorico|پورتوریکو"
"JM|JAM|jamaica|جامائیکا"
)

# English name for a 2-letter code (NL -> netherlands). Used by the alert
# queue so a ban prompt can name the country, not just the code.
cc_name() {
    local key entry code rest
    key="$(norm_cc "$1")"
    [ -z "$key" ] && return 1
    for entry in "${CC_TABLE[@]}"; do
        code="${entry%%|*}"
        [ "$code" = "$key" ] || continue
        rest="${entry#*|}"   # strip CODE|
        rest="${rest#*|}"    # strip A3|
        printf '%s' "${rest%%|*}"
        return 0
    done
    return 1
}

# The three predicates below split a row's names on '|' with a local IFS.
# (Table names are stored lowercase — the caller lowercases the input.)

# 0 when the row carries this exact alpha-3 / name / alias
# (alpha-3 codes are uppercase in the table, names lowercase)
cc_has_name() {
    local entry="$1" key="$2" rest field
    rest="${entry#*|}"
    local IFS='|'
    for field in $rest; do case "${field,,}" in "$key") return 0 ;; esac; done
    return 1
}

# 0 when any name/alias of the row starts with this key
cc_has_prefix() {
    local entry="$1" key="$2" rest field
    rest="${entry#*|}"; rest="${rest#*|}"
    local IFS='|'
    for field in $rest; do case "$field" in "$key"*) return 0 ;; esac; done
    return 1
}

# 0 when this key appears anywhere inside a name/alias of the row
cc_has_part() {
    local entry="$1" key="$2" rest field
    rest="${entry#*|}"; rest="${rest#*|}"
    local IFS='|'
    for field in $rest; do case "$field" in *"$key"*) return 0 ;; esac; done
    return 1
}

# 0 when an ASCII name/alias of the row is within $3 edits of the key
# (a length pre-filter keeps the expensive distance call rare)
cc_close_match() {
    local entry="$1" key="$2" max="$3" rest field lk=${#2} lf
    rest="${entry#*|}"; rest="${rest#*|}"
    local IFS='|'
    for field in $rest; do
        case "$field" in *[!a-z0-9]*) continue ;; esac
        lf=${#field}
        if [ "$lf" -lt $((lk - max)) ] || [ "$lf" -gt $((lk + max)) ]; then continue; fi
        [ "$(lev_dist "$key" "$field")" -le "$max" ] && return 0
    done
    return 1
}

# Levenshtein distance (ASCII strings only) — prints the distance
lev_dist() {
    local a="$1" b="$2" la=${#1} lb=${#2} i j cost del ins sub
    local -a prev cur
    for ((j = 0; j <= lb; j++)); do prev[j]=$j; done
    for ((i = 1; i <= la; i++)); do
        cur[0]=$i
        for ((j = 1; j <= lb; j++)); do
            cost=1; [ "${a:i-1:1}" = "${b:j-1:1}" ] && cost=0
            del=$((prev[j] + 1)); ins=$((cur[j-1] + 1)); sub=$((prev[j-1] + cost))
            cur[j]=$del
            [ "$ins" -lt "${cur[j]}" ] && cur[j]=$ins
            [ "$sub" -lt "${cur[j]}" ] && cur[j]=$sub
        done
        prev=("${cur[@]}")
    done
    printf '%s\n' "${prev[$lb]:-$lb}"
}

# Comma-joined candidates for a helpful "did you mean" line:
#   "TR (turkey), TM (turkmenistan)"
cc_suggest() {
    local key="$1" entry code name out=""
    [ -z "$key" ] && return 0
    for entry in "${CC_TABLE[@]}"; do
        code="${entry%%|*}"
        if cc_has_prefix "$entry" "$key" || cc_has_part "$entry" "$key"; then
            name="${entry#*|}"; name="${name#*|}"; name="${name%%|*}"
            out="${out:+$out, }$code ($name)"
        fi
    done
    # nothing similar by name? fall back to close (typo) matches
    if [ -z "$out" ]; then
        case "$key" in *[!a-z0-9]*) return 0 ;; esac
        [ "${#key}" -ge 5 ] || return 0
        for entry in "${CC_TABLE[@]}"; do
            code="${entry%%|*}"
            if cc_close_match "$entry" "$key" 2; then
                name="${entry#*|}"; name="${name#*|}"; name="${name%%|*}"
                out="${out:+$out, }$code ($name)"
            fi
        done
    fi
    printf '%s' "$out"
}

# resolve_cc <token> -> prints ISO alpha-2 code, or fails when unknown
# Accepts: 2-letter code, alpha-3, exact English/Persian name or alias,
# a UNIQUE name prefix ("German" -> DE) or substring ("netherland" ->
# NL), and a UNIQUE single-typo match ("nederlands" -> NL). Anything
# ambiguous is refused — silently allowing the wrong country through a
# firewall is worse than asking again.
resolve_cc() {
    local in key entry code found cnt
    # Whitespace- and case-insensitive, in pure bash: the old version forked
    # a `tr` per table row, which made a 120-country table take seconds.
    in="${1//[[:space:]]/}"
    [ -z "$in" ] && return 1
    if valid_cc "${in^^}"; then printf '%s\n' "${in^^}"; return 0; fi
    key="${in,,}"

    # pass 1: exact match on alpha-3 / English name / Persian name / alias
    for entry in "${CC_TABLE[@]}"; do
        code="${entry%%|*}"
        if cc_has_name "$entry" "$key"; then printf '%s\n' "$code"; return 0; fi
    done

    # pass 2: unique prefix of a name or alias ("German" -> DE)
    found=""; cnt=0
    for entry in "${CC_TABLE[@]}"; do
        code="${entry%%|*}"
        if cc_has_prefix "$entry" "$key"; then found="$code"; cnt=$((cnt + 1)); fi
    done
    if [ "$cnt" -eq 1 ]; then printf '%s\n' "$found"; return 0; fi

    # pass 3: unique substring of any name/alias ("netherland" -> NL)
    found=""; cnt=0
    for entry in "${CC_TABLE[@]}"; do
        code="${entry%%|*}"
        if cc_has_part "$entry" "$key"; then found="$code"; cnt=$((cnt + 1)); fi
    done
    if [ "$cnt" -eq 1 ]; then printf '%s\n' "$found"; return 0; fi

    # pass 4: unique single-typo match ("nederlands" -> NL). ASCII only,
    # and never for short tokens where one edit changes too much.
    case "$key" in *[!a-z0-9]*) return 1 ;; esac
    [ "${#key}" -ge 5 ] || return 1
    found=""; cnt=0
    for entry in "${CC_TABLE[@]}"; do
        code="${entry%%|*}"
        if cc_close_match "$entry" "$key" 2; then found="$code"; cnt=$((cnt + 1)); fi
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
            local hint hkey
            hkey="${cc//[[:space:]]/}"
            hint="$(cc_suggest "${hkey,,}")"
            [ -n "$hint" ] && info "Did you mean: $hint ?"
            info "List every supported name with: vpssec geo names"
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
            local hint hkey
            hkey="${cc//[[:space:]]/}"
            hint="$(cc_suggest "${hkey,,}")"
            [ -n "$hint" ] && info "Did you mean: $hint ?"
            info "List every supported name with: vpssec geo names"
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
    local cc file url missing=()
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
            # Never delete a good list because of one transient failure.
            if [ -s "$file" ]; then
                warn "  $cc: download failed — keeping the cached list"
            else
                warn "  $cc: download failed (check internet access)"
            fi
        fi
        [ -s "$file" ] || missing+=("$cc")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        warn "No usable range list for: ${missing[*]}"
        return 1
    fi
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
    ok "ipset $IPSET_NAME populated ($(geo_ipset_count) entries)."
    # If not a single range landed in the set, the rules that reference it
    # would drop the whole world. Report a failed rebuild instead.
    if [ "$(geo_ipset_count)" -eq 0 ]; then
        err "ipset $IPSET_NAME is empty — no usable country ranges were loaded."
        return 1
    fi
    return 0
}

# ---------- before.rules block ----------

# ---------- safety invariant ----------
# The final-DROP rule must only ever be installed when at least one
# configured COUNTRY has a real range list. A bypass IP alone is not enough:
# that would produce a ruleset that drops the whole world except one address,
# which is exactly how an admin locks themselves out after their ISP
# reassigns their IP.
geo_ruleset_is_safe() {
    load_geo_conf
    local cc
    for cc in $(echo "${GEO_COUNTRIES:-}" | tr ',' ' '); do
        [ -s "$GEO_DIR/$cc.cidr" ] && return 0
    done
    return 1
}

# The rules consult the ipset, not the files, so "the files exist" is not
# proof that the allow-set can actually hold an address. An empty set plus
# the world-DROP rule is a lockout, so a set that could not be populated is
# treated as a failed rebuild.
geo_ipset_count() {
    cmd_ipset list "$IPSET_NAME" 2>/dev/null | grep -c '^[0-9]'
}

geo_rules_text() {
    local bypass=() ip p
    [ -n "$GEO_BYPASS" ] && IFS=',' read -ra bypass <<< "$GEO_BYPASS"
    # Declared tunnel / VPN / proxy ports must keep working with the country
    # filter on: a reverse tunnel is dialled IN from abroad, so it arrives as
    # a NEW connection from a country that may not be on the allow-list.
    load_tunnel_ports
    cat <<EOF
$MARK_BEGIN
# geo filter: allow ONLY the listed countries, drop the rest
EOF
    for ip in "${bypass[@]:-}"; do
        [ -n "$ip" ] && echo "-A ufw-before-input -s $ip -j ACCEPT" || true
    done
    for p in "${TUNNEL_PORTS[@]:-}"; do
        [ -n "$p" ] || continue
        echo "-A ufw-before-input -p tcp --dport $p -j ACCEPT"
        echo "-A ufw-before-input -p udp --dport $p -j ACCEPT"
    done
    cat <<EOF
-A ufw-before-input -m set --match-set $IPSET_NAME src -j ACCEPT
# TUNNEL SAFETY: only NEW inbound connections are dropped. Replies to
# connections this server opened itself (a tunnel client dialling a
# foreign server, panel API calls, updates) are ESTABLISHED traffic and
# must keep flowing — otherwise enabling the country filter would kill
# every outbound tunnel. Loopback is never geo-filtered either.
-A ufw-before-input ! -i lo -m conntrack --ctstate NEW -j DROP
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
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -qx 'Status: active'; then
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

# ---------- the administrator's own connection ----------

geo_confirm_minutes() { printf '%s\n' "$((GEO_CONFIRM_SECONDS / 60))"; }

# The IP the administrator is connecting FROM. This is the address that must
# never be locked out — the server's own public IP is useless for that, which
# is what an earlier version of the CLI wrongly displayed.
geo_admin_client_ip() {
    local ip=""
    if [ -n "${SSH_CONNECTION:-}" ]; then
        ip="${SSH_CONNECTION%% *}"
    elif [ -n "${SSH_CLIENT:-}" ]; then
        ip="${SSH_CLIENT%% *}"
    fi
    printf '%s\n' "$ip"
}

# Is this address allowed after the rules land (in the set, or bypassed)?
geo_ip_allowed() {
    local ip="$1"
    [ -n "$ip" ] || return 1
    case ",${GEO_BYPASS:-}," in *",$ip,"*) return 0 ;; esac
    have_ipset || return 1
    cmd_ipset test "$IPSET_NAME" "$ip" >/dev/null 2>&1
}

# Adds the current SSH client IP to the never-block list when it is not
# already covered by an allowed country, and verifies the result.
geo_protect_admin() {
    local ip
    ip="$(geo_admin_client_ip)"
    if [ -z "$ip" ]; then
        warn "Cannot see the IP you are connected from (running from a console?)."
        warn "The $(geo_confirm_minutes)-minute confirmation window protects you instead."
        return 0
    fi
    if geo_ip_allowed "$ip"; then
        ok "Your current IP ($ip) is already allowed."
        return 0
    fi
    GEO_BYPASS="${GEO_BYPASS:+$GEO_BYPASS,}$ip"
    save_geo_conf
    ok "Your current IP ($ip) is NOT in the allowed countries — added to the never-block list."
    printf '%s BYPASS-AUTO %s (admin SSH client)\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$ip" >> "$GEO_LOG"
    return 0
}

# ---------- confirmation window (the anti-lockout guarantee) ----------

geo_start_confirm_window() {
    ensure_dirs
    rm -f "$GEO_PENDING"
    local now deadline
    now="$(date +%s)"
    deadline=$((now + GEO_CONFIRM_SECONDS))
    printf '%s\n' "$deadline" > "$GEO_PENDING"
    cat > "$VPSSEC_SYSTEMD_DIR/$GEO_GUARD_SERVICE" <<EOF
[Unit]
Description=vps-security GeoIP safety re-open (unconfirmed filter change)

[Service]
Type=oneshot
ExecStart=$SCRIPT_DIR/lib/geoip.sh --confirm-check
EOF
    cat > "$VPSSEC_SYSTEMD_DIR/$GEO_GUARD_TIMER" <<EOF
[Unit]
Description=Re-open the server if a GeoIP change is never confirmed

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=$GEO_GUARD_SERVICE

[Install]
WantedBy=timers.target
EOF
    cmd_systemctl daemon-reload >/dev/null 2>&1 || true
    cmd_systemctl enable --now "$GEO_GUARD_TIMER" >/dev/null 2>&1 || true
    printf '%s PENDING confirmation until %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$deadline" >> "$GEO_LOG"
}

geo_confirm() {
    load_geo_conf
    rm -f "$GEO_PENDING"
    cmd_systemctl disable --now "$GEO_GUARD_TIMER" >/dev/null 2>&1 || true
    rm -f "$VPSSEC_SYSTEMD_DIR/$GEO_GUARD_SERVICE" "$VPSSEC_SYSTEMD_DIR/$GEO_GUARD_TIMER"
    cmd_systemctl daemon-reload >/dev/null 2>&1 || true
    printf '%s CONFIRMED\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$GEO_LOG"
    ok "Confirmed — the country filter stays active (it will no longer re-open by itself)."
    ok "Allowed countries: $(echo "${GEO_COUNTRIES:-}" | tr ',' ' ')"
    info "Changed your mind?  vpssec geo disable   (or the rescue command: vpssec rescue)"
    return 0
}

# Run every minute by the guard timer. If the admin never confirmed the
# change (they lost access) the filter is removed and the server re-opens.
geo_confirm_check() {
    load_geo_conf
    geo_enabled || { rm -f "$GEO_PENDING"; return 0; }
    [ -f "$GEO_PENDING" ] || return 0
    local deadline now
    deadline="$(tr -dc '0-9' < "$GEO_PENDING" 2>/dev/null)"
    now="$(date +%s)"
    case "$deadline$now" in *[!0-9]*|"") return 0 ;; esac
    [ -n "$deadline" ] || return 0
    if [ "$now" -ge "$deadline" ]; then
        warn "GeoIP change was never confirmed — re-opening the server to all countries."
        geo_disable
        rm -f "$GEO_PENDING"
        printf '%s SAFETY unconfirmed geo filter auto-disabled (server re-opened)\n' \
            "$(date '+%Y-%m-%d %H:%M:%S')" >> "$GEO_LOG"
        ok "Run 'vpssec geo enable' again when you are sure your IP is covered."
    fi
    return 0
}

# Emergency: strip the country filter no matter what state the config is in.
geo_panic() {
    warn "Removing the country filter and re-opening the server to everyone..."
    load_geo_conf
    geo_remove_rules
    cmd_ipset destroy "$IPSET_NAME" 2>/dev/null || true
    rm -f "$GEO_PENDING"
    cmd_systemctl disable --now "$GEO_GUARD_TIMER" >/dev/null 2>&1 || true
    cmd_systemctl disable --now vps-security-geo.timer >/dev/null 2>&1 || true
    rm -f "$VPSSEC_SYSTEMD_DIR/$GEO_GUARD_SERVICE" "$VPSSEC_SYSTEMD_DIR/$GEO_GUARD_TIMER" \
          "$VPSSEC_SYSTEMD_DIR/vps-security-geo.service" "$VPSSEC_SYSTEMD_DIR/vps-security-geo.timer"
    cmd_systemctl daemon-reload >/dev/null 2>&1 || true
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -qx 'Status: active'; then
        cmd_ufw reload >/dev/null 2>&1 || true
    fi
    GEO_ENABLED=0
    save_geo_conf
    printf '%s PANIC geo filter removed\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$GEO_LOG"
    ok "Country filter removed — the server is reachable from every country again."
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

    # SAFETY 1: EVERY configured country must have a range list.
    # A partial download used to be accepted, which produced a ruleset that
    # allowed ONLY whichever country happened to download — so an admin in
    # Iran who also whitelisted the Netherlands lost SSH the moment the IR
    # download failed. Refuse to enable in that state.
    if ! geo_download; then
        geo_strip_if_unsafe || true
        err "Country lists are incomplete (see the failures above) — geo filtering NOT enabled."
        err "The server remains accessible from ALL countries. Re-run --enable when the downloads work."
        return 1
    fi
    # SAFETY 2: never write the world-DROP rule with an empty allow-set.
    # This covers a rebuild that produced no usable range (empty set = lockout).
    if ! geo_ipset_rebuild; then
        geo_remove_rules
        cmd_ipset destroy "$IPSET_NAME" 2>/dev/null || true
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -qx 'Status: active'; then
            cmd_ufw reload >/dev/null 2>&1 || true
        fi
        printf '%s SAFETY allow-set empty — geo rules removed, server open to all\n' \
            "$(date '+%Y-%m-%d %H:%M:%S')" >> "$GEO_LOG"
        err "The allow-set is empty (no usable country ranges) — country filtering NOT enabled."
        err "Country filtering NOT enabled — the server remains accessible from ALL countries."
        return 1
    fi
    if ! geo_ruleset_is_safe; then
        geo_strip_if_unsafe || true
        err "Country lists are empty (download failed?) — geo filtering NOT enabled."
        err "The server remains accessible from ALL countries. Fix internet access and re-run --enable."
        return 1
    fi
    # SAFETY 3: allow the connection the administrator is using right now.
    geo_protect_admin || true
    geo_write_rules || die "writing ufw rules failed."
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -qx 'Status: active'; then
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
    # SAFETY 4: the confirmation window — if this connection dies, doing
    # nothing re-opens the server by itself.
    geo_start_confirm_window
    ok "Country allow-list ENABLED — ONLY these countries can reach this server:"
    ok "  $(echo "$GEO_COUNTRIES" | tr ',' ' ')"
    info "Every other country is blocked now (allow-list, not a block-list)."
    warn "SAFETY: confirm within $(geo_confirm_minutes) minutes:  vpssec geo confirm"
    warn "If you lose SSH, just WAIT — the filter removes itself and the server re-opens."
}

geo_disable() {
    load_geo_conf
    geo_remove_rules
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -qx 'Status: active'; then
        cmd_ufw reload >/dev/null 2>&1 || true
    fi
    cmd_systemctl disable --now vps-security-geo.timer 2>/dev/null || true
    # a disabled filter must never leave a pending confirmation behind
    cmd_systemctl disable --now "$GEO_GUARD_TIMER" 2>/dev/null || true
    rm -f "$GEO_PENDING"
    rm -f "$VPSSEC_SYSTEMD_DIR"/vps-security-geo.{service,timer}
    rm -f "$VPSSEC_SYSTEMD_DIR/$GEO_GUARD_SERVICE" "$VPSSEC_SYSTEMD_DIR/$GEO_GUARD_TIMER"
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

# ---------- name lookup table ----------
# Everything the country resolver understands, so an admin never has to
# guess: code, primary English name and the accepted aliases.
cc_list_all() {
    local entry code rest names first
    printf '  %-4s %-22s %s\n' "CODE" "TYPE THIS NAME" "ALSO ACCEPTS"
    printf '  %s\n' "--------------------------------------------------------------"
    for entry in "${CC_TABLE[@]}"; do
        code="${entry%%|*}"
        rest="${entry#*|}"; rest="${rest#*|}"
        first="${rest%%|*}"
        names="${rest#*|}"
        if [ "$names" = "$rest" ]; then names=""; else names="${names//|/, }"; fi
        printf '  %-4s %-22s %s\n' "$code" "$first" "$names"
    done
    printf '\n  %s countries supported. Type a code, a full name or a\n' "${#CC_TABLE[@]}"
    printf '  unique abbreviation, e.g.  IR   Germany   آلمان   netherlands\n'
}

case "${1:-}" in
    --add)    shift; need_root; geo_add_countries "${1:-}";;
    --remove) shift; need_root; geo_remove_countries "${1:-}";;
    --list)   geo_list ;;
    --names)  cc_list_all ;;
    --cc-name) shift; cc_name "${1:-}" || true ;;
    --enable) need_root; geo_enable ;;
    --confirm) need_root; geo_confirm ;;
    --confirm-check) need_root; geo_confirm_check ;;
    --panic) need_root; geo_panic ;;
    --disable) need_root; geo_disable ;;
    --bypass) shift; geo_bypass "${1:-}" "${2:-}" ;;
    --refresh) need_root; geo_refresh ;;
    --ipset-restore)
        # SAFETY at boot: if the on-disk config is unsafe (no countries /
        # empty lists / no bypass), remove any geo rules so the server is
        # never left blocked from the whole world after a reboot.
        load_geo_conf
        if ! geo_ruleset_is_safe; then
            geo_strip_if_unsafe || true
            exit 0
        fi
        # An unconfirmed change that already expired must not come back at
        # boot — otherwise a reboot would re-lock a server the guard just
        # re-opened.
        if [ -f "$GEO_PENDING" ]; then
            GEO_DL_BY="$(tr -dc '0-9' < "$GEO_PENDING" 2>/dev/null)"
            GEO_DL_NOW="$(date +%s)"
            if [ -n "$GEO_DL_BY" ] && [ "$GEO_DL_NOW" -ge "$GEO_DL_BY" ]; then
                geo_strip_if_unsafe || true
                rm -f "$GEO_PENDING"
                exit 0
            fi
        fi
        # SAFETY: only rewrite the rules when the allow-set could actually be
        # rebuilt. At boot the ipset is recreated from scratch, so a failed
        # rebuild means an empty set — writing the world-DROP rule then would
        # lock the server out on every restart.
        if geo_ipset_rebuild; then
            geo_write_rules 2>/dev/null || true
        else
            geo_remove_rules
            printf '%s SAFETY ipset rebuild empty at boot — geo rules left out, server open to all\n' \
                "$(date '+%Y-%m-%d %H:%M:%S')" >> "$GEO_LOG"
        fi
        ;;
    --health) geo_enabled ;;
    *) die "usage: geoip.sh (--add <CC,..>|--remove <CC,..>|--list|--names|--cc-name <CC>|--enable|--confirm|--panic|--disable|--bypass|--refresh|--health)" ;;
esac
