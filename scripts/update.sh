#!/usr/bin/env bash
# vps-security — update in place from GitHub
set -euo pipefail
TARGET="/opt/vps-security"
BRANCH="main"

if [ ! -d "$TARGET/.git" ]; then
    echo "[✗] vps-security is not installed at $TARGET" >&2
    echo "    Run: bash <(curl -fsSL https://raw.githubusercontent.com/amir12120/vps-security/main/install.sh)" >&2
    exit 1
fi

echo "[i] Updating vps-security..."
git -C "$TARGET" fetch origin "$BRANCH"
git -C "$TARGET" reset --hard "origin/$BRANCH"
chmod +x "$TARGET/vpssec" "$TARGET"/lib/*.sh "$TARGET"/test/*.sh 2>/dev/null || true
ln -sf "$TARGET/vpssec" /usr/local/bin/vpssec

echo "[✓] vps-security updated to the latest version."
echo "[i] Restarting services..."
systemctl restart vps-security-guard.service 2>/dev/null || true
systemctl restart vps-security-monitor.timer 2>/dev/null || true
echo "[i] Done."
