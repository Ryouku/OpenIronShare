#!/bin/bash
set -euo pipefail

# IronShare deployment script for Ubuntu amd64
# Run as root: sudo bash install.sh

BINARY="./ironshare"
INSTALL_DIR="/opt/ironshare"
DATA_DIR="${INSTALL_DIR}/data"
SERVICE_FILE="./ironshare.service"
NGINX_CONF="./ironshare.conf"

echo "=== IronShare Deployment ==="

# Verify binary exists
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY"
    echo "Build it first: see README"
    exit 1
fi

# Create service user (no login, no home)
if ! id -u ironshare &>/dev/null; then
    echo "[1/6] Creating ironshare user..."
    useradd --system --no-create-home --shell /usr/sbin/nologin ironshare
else
    echo "[1/6] User ironshare already exists"
fi

# Create directories
echo "[2/6] Creating directories..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR"

# Copy binary
echo "[3/6] Installing binary..."
cp "$BINARY" "$INSTALL_DIR/ironshare"
chmod 755 "$INSTALL_DIR/ironshare"

# Create empty DB file if needed (migrations run on startup)
touch "$DATA_DIR/ironshare.db"

# Set ownership
chown -R ironshare:ironshare "$INSTALL_DIR"
chmod 700 "$DATA_DIR"
chmod 600 "$DATA_DIR/ironshare.db"

# Install systemd service
echo "[4/6] Installing systemd service..."
cp "$SERVICE_FILE" /etc/systemd/system/ironshare.service
systemctl daemon-reload

# Install nginx config (if nginx is installed)
if command -v nginx &>/dev/null; then
    echo "[5/6] Installing nginx config..."
    if [ -f "$NGINX_CONF" ]; then
        cp "$NGINX_CONF" /etc/nginx/sites-available/ironshare
        ln -sf /etc/nginx/sites-available/ironshare /etc/nginx/sites-enabled/ironshare
        echo "  -> Edit /etc/nginx/sites-available/ironshare:"
        echo "     - Replace YOUR_DOMAIN with your domain"
        echo "     - Place your SSL cert at /etc/ssl/certs/ironshare.pem"
        echo "     - Place your SSL key at /etc/ssl/private/ironshare.key"
        nginx -t && systemctl reload nginx
    fi
else
    echo "[5/6] Nginx not found, skipping config install"
fi

# Enable and start
echo "[6/6] Starting IronShare..."
systemctl enable ironshare
systemctl start ironshare

sleep 2

if systemctl is-active --quiet ironshare; then
    echo ""
    echo "=== IronShare is running ==="
    echo "  Status:  systemctl status ironshare"
    echo "  Logs:    journalctl -u ironshare -f"
    echo "  Health:  curl http://127.0.0.1:3000/health"
    echo ""
    echo "Next steps:"
    echo "  1. Edit /etc/nginx/sites-available/ironshare (set domain + certs)"
    echo "  2. sudo nginx -t && sudo systemctl reload nginx"
else
    echo "ERROR: Service failed to start"
    echo "Check: journalctl -u ironshare -n 50"
    exit 1
fi
