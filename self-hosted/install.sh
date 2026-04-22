#!/usr/bin/env bash
# AIAuth Enterprise — non-Docker install script (Phase C.1)
#
# For customer IT teams that can't run Docker. Creates a Python venv,
# installs dependencies, sets up a systemd service, optional nginx
# reverse proxy + certbot SSL.
#
# Tested on Debian 12, Ubuntu 22.04 LTS, RHEL 9 (with dnf).
#
# Usage (as root):
#   sudo ./install.sh /path/to/config.yaml
#
# Idempotent. Re-running upgrades an existing install.

set -euo pipefail

CONFIG_SRC="${1:-}"
if [[ -z "$CONFIG_SRC" ]]; then
  echo "Usage: sudo $0 /path/to/config.yaml"
  exit 1
fi
[[ -f "$CONFIG_SRC" ]] || { echo "Config not found: $CONFIG_SRC"; exit 1; }
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR=/opt/aiauth
CONFIG_PATH=/etc/aiauth/config.yaml
SERVICE_USER=aiauth
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[install] Repo root: $REPO_ROOT"
echo "[install] Install dir: $INSTALL_DIR"

# ---------- 1. System deps ----------
if command -v apt-get >/dev/null; then
  apt-get update
  apt-get install -y --no-install-recommends python3 python3-venv python3-pip \
    sqlite3 curl nginx certbot python3-certbot-nginx
elif command -v dnf >/dev/null; then
  dnf install -y python3 python3-pip sqlite nginx certbot python3-certbot-nginx
else
  echo "[install] WARNING: couldn't detect apt-get or dnf. Install manually: python3 sqlite3 nginx certbot."
fi

# ---------- 2. System user + directories ----------
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home "$INSTALL_DIR" --shell /bin/false "$SERVICE_USER"
fi
mkdir -p "$INSTALL_DIR" /etc/aiauth /var/lib/aiauth
cp -r "$REPO_ROOT"/{server.py,requirements.txt,index.html,verify.html,logo.png,docs,templates,self-hosted} "$INSTALL_DIR"/

# Config file
cp "$CONFIG_SRC" "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH"

# Permissions
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" /var/lib/aiauth /etc/aiauth

# ---------- 3. Python venv ----------
if [[ ! -d "$INSTALL_DIR/venv" ]]; then
  "$PYTHON_BIN" -m venv "$INSTALL_DIR/venv"
fi
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# ---------- 4. Bootstrap ----------
echo "[install] Running bootstrap.py..."
(cd "$INSTALL_DIR" && sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" self-hosted/scripts/bootstrap.py --config "$CONFIG_PATH")

# ---------- 5. Systemd unit ----------
cp "$REPO_ROOT/self-hosted/systemd/aiauth.service" /etc/systemd/system/aiauth.service
systemctl daemon-reload
systemctl enable aiauth

# ---------- 6. nginx vhost (optional) ----------
SERVER_URL=$(grep "^server_url:" "$CONFIG_PATH" | head -1 | cut -d'"' -f2)
SERVER_HOST=$(echo "$SERVER_URL" | sed -E 's|https?://||; s|/.*||')
if [[ -n "$SERVER_HOST" ]]; then
  sed "s|{{SERVER_HOST}}|$SERVER_HOST|g" "$REPO_ROOT/self-hosted/nginx/aiauth.conf.template" > /etc/nginx/sites-available/aiauth
  ln -sf /etc/nginx/sites-available/aiauth /etc/nginx/sites-enabled/aiauth
  nginx -t && systemctl reload nginx
  echo "[install] nginx vhost configured for $SERVER_HOST"
  echo "[install] Run 'certbot --nginx -d $SERVER_HOST' to obtain TLS cert."
fi

# ---------- 7. Start service ----------
systemctl restart aiauth
sleep 2
if systemctl is-active --quiet aiauth; then
  echo ""
  echo "=========================================================="
  echo "AIAuth Enterprise running. Verify:"
  echo "  curl -fsS http://localhost:8100/health"
  echo "  systemctl status aiauth"
  echo "  journalctl -u aiauth -f"
  echo "=========================================================="
else
  echo "ERROR: service did not start. Check logs:"
  echo "  journalctl -u aiauth -n 50 --no-pager"
  exit 1
fi
