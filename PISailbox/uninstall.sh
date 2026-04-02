#!/usr/bin/env bash
set -e
echo "Removing PiSailBox…"
systemctl stop    pisailbox.service  2>/dev/null || true
systemctl disable pisailbox.service  2>/dev/null || true
rm -f /etc/systemd/system/pisailbox.service
systemctl daemon-reload
rm -rf /opt/pisailbox
echo "Done. Data in ~/pisailbox_data was NOT removed."
