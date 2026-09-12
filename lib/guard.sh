#!/usr/bin/env bash
# ============================================================
# vps-security — local guard API
#
# A tiny dependency-free HTTP endpoint (bash + /dev/tcp) that
# exposes monitor state for a future remote dashboard. Binds to
# 127.0.0.1 by default; never expose it publicly without a
# reverse proxy with authentication.
#
# Endpoints:
#   GET /health   -> {"status":"ok"}
#   GET /status   -> allowed ports, block list, pending alerts, events
#
# NOTE: This listener answers ONE request per connection, serially.
# It is intentionally minimal; a future release may move it to Node.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

GUARD_PORT="18080"
GUARD_HOST="${GUARD_HOST:-127.0.0.1}"
# Reserved for future bash-side request body handling; the Python server
# (cmd_serve_py) enforces its own limits.
MAX_BODY_BYTES=8192  # shellcheck disable=SC2034 # intentionally kept

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' '
}

build_status_json() {
    ensure_dirs
    load_allowed_ports
    local allowed="[" first=1 p
    for p in "${ALLOWED_PORTS[@]:-}"; do
        [ -z "$p" ] && continue
        [ $first -eq 1 ] || allowed+=","
        allowed+="\"$p\""
        first=0
    done
    allowed+="]"

    local blocked="["
    first=1
    if [ -f "$BLOCK_LIST_FILE" ]; then
        while IFS= read -r p || [ -n "$p" ]; do
            [ -z "$p" ] && continue
            [ $first -eq 1 ] || blocked+=","
            blocked+="\"$p\""
            first=0
        done < "$BLOCK_LIST_FILE"
    fi
    blocked+="]"

    local pending_n=0
    [ -f "$VPSSEC_STATE_DIR/pending-alerts.list" ] && \
        pending_n="$(grep -cE '^[0-9]+\|' "$VPSSEC_STATE_DIR/pending-alerts.list" || true)"

    local events="[]"
    if [ -f "$BLOCK_LOG" ]; then
        events="$(tail -n 20 "$BLOCK_LOG" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read().splitlines()))' 2>/dev/null || printf '[]')"
    fi

    printf '{"status":"ok","allowed":%s,"blocked":%s,"pending_alerts":%s,"events":%s}\n' \
        "$allowed" "$blocked" "${pending_n:-0}" "$events"
}

serve_one() {
    # Read request headers (and discard any body)
    # shellcheck disable=SC2034  # req/method parsed for clarity; routing uses path
    local req line method path
    IFS=' ' read -r method path _ <&"$1" 2>/dev/null || return 0
    # consume remaining headers
    while IFS= read -r line <&"$1" && [ "$line" != $'\r' ] && [ -n "$line" ]; do :; done

    local out
    case "$path" in
        /health)
            out='{"status":"ok"}'
            ;;
        /status)
            out="$(build_status_json)"
            ;;
        *)
            out='{"error":"not found"}'
            printf 'HTTP/1.1 404 Not Found\r\n' >&"$1" 2>/dev/null
            printf 'Content-Type: application/json\r\n' >&"$1" 2>/dev/null
            printf 'Content-Length: %s\r\n\r\n%s' "$(printf '%s' "$out" | wc -c)" "$out" >&"$1" 2>/dev/null
            return 0
            ;;
    esac

    printf 'HTTP/1.1 200 OK\r\n' >&"$1" 2>/dev/null
    printf 'Content-Type: application/json\r\n' >&"$1" 2>/dev/null
    printf 'Content-Length: %s\r\n\r\n%s' "$(printf '%s' "$out" | wc -c)" "$out" >&"$1" 2>/dev/null
}

cmd_serve() {
    need_root
    info "guard API listening on $GUARD_HOST:$GUARD_PORT (Ctrl+C to stop)"
    while :; do
        # fd 3 listener
        if ! exec 3<>/dev/tcp/"$GUARD_HOST"/"$GUARD_PORT" 2>/dev/null; then
            err "cannot bind $GUARD_HOST:$GUARD_PORT — is another service using it?"
            sleep 5
            continue
        fi
        :
    done
}

# NOTE: bash's /dev/tcp is client-only — it cannot LISTEN. Real serving is
# delegated to a minimal Python http.server (present on every Ubuntu).
cmd_serve_py() {
    need_root
    exec python3 - "$GUARD_PORT" <<'PYEOF'
import json, os, subprocess, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = os.environ.get("VPSSEC_STATE_DIR", "/var/lib/vps-security")
CONF  = os.environ.get("VPSSEC_CONF_DIR",  "/etc/vps-security")

def read_ports(path, split_on_pipe=False):
    out = []
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line:
                    continue
                out.append(line.split("|")[-1] if split_on_pipe else line)
    except OSError:
        pass
    return out

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok"})
        elif self.path == "/status":
            blocked = read_ports(os.path.join(STATE, "blocked-ports.list"), split_on_pipe=True)
            allowed = read_ports(os.path.join(CONF, "allowed-ports.list"))
            # Suspicious events detected but NOT yet blocked: the approval
            # model means this number can be non-zero while nothing is
            # firewalled, which a dashboard must show separately.
            pending = read_ports(os.path.join(STATE, "pending-alerts.list"))
            events = []
            log = os.path.join(STATE, "port-blocks.log")
            try:
                with open(log) as f:
                    events = f.read().splitlines()[-20:]
            except OSError:
                pass
            self._json(200, {"status": "ok", "allowed": allowed, "blocked": blocked,
                             "pending_alerts": len(pending), "events": events})
        else:
            self._json(404, {"error": "not found"})

HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYEOF
}

case "${1:-}" in
    --serve)
        shift
        if [ "${1:-}" = "--port" ] && is_valid_port "${2:-}"; then
            GUARD_PORT="$2"
        fi
        cmd_serve_py
        ;;
    *) die "usage: guard.sh --serve [--port N]" ;;
esac
