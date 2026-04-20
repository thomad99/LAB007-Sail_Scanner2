#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# PiSailBox install script for Raspberry Pi 3B, Pi OS Lite 64-bit
# Run as:  chmod +x install.sh && sudo bash install.sh
# ──────────────────────────────────────────────────────────────────────────────
set -e

INSTALL_DIR="/opt/pisailbox"
SERVICE_FILE="pisailbox.service"
USER="pi"
SERVER_URL="${PISAILBOX_SERVER:-https://lovesailing.ai}"   # override via env var

echo "======================================"
echo " PiSailBox Installer"
echo " Server: $SERVER_URL"
echo "======================================"

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/6] Updating packages…"
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3-pip \
    python3-serial \
    python3-requests \
    python3-picamera2 \
    libcamera-apps \
    ffmpeg \
    minicom \
    network-manager \
    modemmanager \
    usb-modeswitch

# ── 2. Enable camera in firmware ──────────────────────────────────────────────
echo "[2/6] Enabling camera…"
if ! grep -q "camera_auto_detect=1" /boot/config.txt 2>/dev/null; then
    echo "camera_auto_detect=1" >> /boot/config.txt
fi

# ── 3. Serial port permissions ────────────────────────────────────────────────
echo "[3/6] Setting serial port permissions…"
usermod -aG dialout $USER

# Allow the Pi user to reboot or shut down from PiControl (passwordless sudo for those binaries only)
echo "[3b/6] Sudo rules for remote reboot / shutdown…"
echo "$USER ALL=(ALL) NOPASSWD: /sbin/reboot, /usr/sbin/reboot, /sbin/shutdown, /usr/sbin/shutdown" > /etc/sudoers.d/99-pisailbox-reboot
chmod 440 /etc/sudoers.d/99-pisailbox-reboot
if visudo -cf /etc/sudoers.d/99-pisailbox-reboot 2>/dev/null; then
    echo "   Remote reboot/shutdown sudo rules installed ✓"
else
    echo "   WARNING: sudoers check failed — removing rule (remote reboot/shutdown from portal will not work)"
    rm -f /etc/sudoers.d/99-pisailbox-reboot
fi

# Disable serial console to free up ttyUSB ports
if systemctl is-active --quiet serial-getty@ttyS0.service 2>/dev/null; then
    systemctl stop serial-getty@ttyS0.service
    systemctl disable serial-getty@ttyS0.service
fi
if systemctl is-active --quiet serial-getty@ttyAMA0.service 2>/dev/null; then
    systemctl stop serial-getty@ttyAMA0.service
    systemctl disable serial-getty@ttyAMA0.service
fi

# Ensure ttyAMA0 is accessible to the dialout group (needed on some Pi OS builds).
cat > /etc/udev/rules.d/99-pisailbox-uart.rules <<'EOF'
KERNEL=="ttyAMA0", GROUP="dialout", MODE="0660"
EOF
udevadm control --reload-rules || true
udevadm trigger --name-match=ttyAMA0 || true

# ── 4. 4G / SIM card setup ────────────────────────────────────────────────────
echo "[4/6] Configuring 4G modem (ModemManager)…"
systemctl enable ModemManager
systemctl start  ModemManager

# Wait for modem to be detected
echo "   Waiting 5s for modem…"
sleep 5

# Check if modem found
if mmcli -L 2>/dev/null | grep -q "Modem"; then
    echo "   Modem detected ✓"
    MODEM_PATH=$(mmcli -L 2>/dev/null | grep -o '/org/freedesktop/ModemManager[^ ]*' | head -1)

    # Optionally set APN (edit if your SIM needs a specific APN)
    # Uncomment and set your APN:
    # APN="internet"
    # nmcli connection add type gsm ifname '*' con-name pisailbox-4g apn "$APN"
    # nmcli connection up pisailbox-4g

    echo "   NOTE: If 4G does not connect automatically, run:"
    echo "   sudo nmcli connection add type gsm ifname '*' con-name pisailbox-4g apn YOUR_APN"
    echo "   sudo nmcli connection up pisailbox-4g"
else
    echo "   WARNING: Modem not detected. Make sure HAT is powered and SIM is inserted."
fi

# ── 5. Install application ────────────────────────────────────────────────────
echo "[5/6] Installing PiSailBox…"
mkdir -p $INSTALL_DIR
cp -r "$(dirname "$0")"/* $INSTALL_DIR/
chown -R $USER:$USER $INSTALL_DIR

# Write server URL into config.
# Important: anchor the match at line start so we do NOT rewrite SIM_SERVER_URL.
sed -i "s|^SERVER_URL[[:space:]]*=.*$|SERVER_URL = os.environ.get(\"PISAILBOX_SERVER\", \"$SERVER_URL\")|" \
    $INSTALL_DIR/config.py

# Create data directory
mkdir -p /home/$USER/pisailbox_data/photos
mkdir -p /home/$USER/pisailbox_data/videos
chown -R $USER:$USER /home/$USER/pisailbox_data

# ── 6. Install systemd service ────────────────────────────────────────────────
echo "[6/6] Installing systemd service…"
cp $INSTALL_DIR/$SERVICE_FILE /etc/systemd/system/pisailbox.service
# Inject server URL
sed -i "s|Environment=PISAILBOX_SERVER=.*|Environment=PISAILBOX_SERVER=$SERVER_URL|" \
    /etc/systemd/system/pisailbox.service

systemctl daemon-reload
systemctl enable pisailbox.service
systemctl start  pisailbox.service

echo ""
echo "======================================"
echo " Installation complete!"
echo ""
echo " Service status:  sudo systemctl status pisailbox"
echo " Live logs:       sudo journalctl -u pisailbox -f"
echo " Stop service:    sudo systemctl stop pisailbox"
echo " Uninstall:       sudo bash $INSTALL_DIR/uninstall.sh"
echo "======================================"
