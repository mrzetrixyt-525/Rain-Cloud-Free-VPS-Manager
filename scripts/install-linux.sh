#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

APP_DIR="/opt/rgnodes-vps-protect"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE="rgnodes-vps-protect.service"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo bash scripts/install-linux.sh" >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "This installer targets Debian/Ubuntu (apt)." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip nftables iptables

install -d -m 0755 "$APP_DIR"
cp -a "$SRC_DIR/app" "$APP_DIR/"
cp -a "$SRC_DIR/config" "$APP_DIR/"
cp -a "$SRC_DIR/static" "$APP_DIR/"
cp -a "$SRC_DIR/templates" "$APP_DIR/"
cp -a "$SRC_DIR/scripts" "$APP_DIR/"
cp -a "$SRC_DIR/requirements.txt" "$APP_DIR/"
cp -a "$SRC_DIR/README.md" "$APP_DIR/" 2>/dev/null || true
install -d -m 0750 "$APP_DIR/logs"

python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/pip" install --no-cache-dir -r "$APP_DIR/requirements.txt"

if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files >/dev/null 2>&1; then
    cat > "/etc/systemd/system/$SERVICE" <<EOF
[Unit]
Description=RG Nodes VPS Protect - real-time host protection
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/app/main.py
Restart=always
RestartSec=3
TimeoutStopSec=10
User=root
Group=root
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$APP_DIR/logs $APP_DIR/config
LimitNOFILE=131072

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE"
    systemctl restart "$SERVICE"
    sleep 2
    systemctl --no-pager --full status "$SERVICE" || true
else
    echo "systemd is unavailable; use $APP_DIR/scripts/run-forever.sh"
    echo "For Pterodactyl, use: $APP_DIR/.venv/bin/python $APP_DIR/app/main.py"
fi

echo
echo 'RG Nodes VPS Protect installed.'
echo 'Dashboard: http://SERVER-IP:5665'
echo "Health:    http://SERVER-IP:5665/health"
echo "Config:    $APP_DIR/config/config.json"
