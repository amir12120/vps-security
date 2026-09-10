#!/usr/bin/env bash
# ============================================================
# vps-security — one-line bootstrap installer
#
# Usage (as root on a fresh Ubuntu/Debian server):
#   bash <(curl -fsSL https://raw.githubusercontent.com/amir12120/vps-security/main/install.sh)
#
# Clones/updates the repo into /opt/vps-security and launches the
# interactive vpssec CLI install flow.
# ============================================================
set -euo pipefail

REPO_URL="${VPSSEC_REPO_URL:-https://github.com/amir12120/vps-security.git}"
BRANCH="${VPSSEC_BRANCH:-main}"
TARGET="/opt/vps-security"

echo "=============================================="
echo "  vps-security — bootstrap installer"
echo "=============================================="

# Must be root
if [ "$(id -u)" -ne 0 ]; then
    echo "[✗] Please run as root:  sudo bash install.sh" >&2
    exit 1
fi

# Debian/Ubuntu check
if [ ! -f /etc/debian_version ]; then
    echo "[✗] This installer supports Debian/Ubuntu only." >&2
    exit 1
fi

# git
if ! command -v git >/dev/null 2>&1; then
    echo "[i] Installing git..."
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y git curl ca-certificates
fi

# Clone or update
if [ -d "$TARGET/.git" ]; then
    echo "[i] Updating existing copy in $TARGET..."
    git -C "$TARGET" fetch origin "$BRANCH"
    git -C "$TARGET" reset --hard "origin/$BRANCH"
else
    echo "[i] Cloning $REPO_URL into $TARGET..."
    rm -rf "$TARGET"
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TARGET"
fi

chmod +x "$TARGET/vpssec" "$TARGET"/lib/*.sh "$TARGET"/test/*.sh 2>/dev/null || true

# Convenience symlink
ln -sf "$TARGET/vpssec" /usr/local/bin/vpssec

echo
echo "[✓] Repository ready at $TARGET"
echo "[i] Launching the interactive installer — answer the prompts..."
echo
exec bash "$TARGET/vpssec" install
