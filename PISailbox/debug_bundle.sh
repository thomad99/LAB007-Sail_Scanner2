#!/usr/bin/env bash
# Collects PiSailBox diagnostics into one text file.
# Usage:
#   chmod +x debug_bundle.sh
#   sudo ./debug_bundle.sh
# Optional:
#   sudo ./debug_bundle.sh /tmp

set -uo pipefail

TARGET_HOME="$HOME"
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  SUDO_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  if [[ -n "${SUDO_HOME:-}" ]]; then
    TARGET_HOME="$SUDO_HOME"
  fi
fi

OUT_DIR="${1:-$TARGET_HOME/pisailbox_data}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT_FILE="$OUT_DIR/pisailbox-debug-$TS.txt"

mkdir -p "$OUT_DIR"

print_header() {
  local title="$1"
  {
    echo
    echo "================================================================"
    echo "$title"
    echo "================================================================"
  } >> "$OUT_FILE"
}

run_cmd() {
  local title="$1"
  local cmd="$2"
  print_header "$title"
  {
    echo "\$ $cmd"
    echo
    bash -lc "$cmd"
    echo
  } >> "$OUT_FILE" 2>&1 || {
    echo "[command failed, continuing]" >> "$OUT_FILE"
    echo >> "$OUT_FILE"
  }
}

{
  echo "PiSailBox Debug Bundle"
  echo "Generated: $(date -Is)"
  echo "User: $(id -un 2>/dev/null || echo unknown)"
  echo "Hostname: $(hostname 2>/dev/null || echo unknown)"
  echo "PWD: $(pwd)"
  echo "Report file: $OUT_FILE"
} > "$OUT_FILE"

run_cmd "System Overview" "date; uptime; whoami; id; uname -a; cat /etc/os-release"
run_cmd "Disk / Memory" "df -h; lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINT; free -h"
run_cmd "CPU / Temperature / Throttling" "vcgencmd measure_temp 2>/dev/null || true; vcgencmd get_throttled 2>/dev/null || true"
run_cmd "Raspberry Pi Hardware" "cat /proc/cpuinfo; dmesg | grep -Ei 'raspberry|mmc|sd|usb|camera' | tail -n 200"

run_cmd "Camera Checks" "libcamera-hello --list-cameras 2>/dev/null || true; vcgencmd get_camera 2>/dev/null || true"
run_cmd "USB / Serial Devices" "lsusb 2>/dev/null || true; ls -l /dev/ttyUSB* /dev/ttyACM* /dev/serial* 2>/dev/null || true"

run_cmd "Network Interfaces" "ip -br a; ip route; resolvectl status 2>/dev/null || cat /etc/resolv.conf"
run_cmd "NetworkManager Summary" "nmcli general status 2>/dev/null || true; nmcli device status 2>/dev/null || true; nmcli -f NAME,TYPE,DEVICE connection show --active 2>/dev/null || true"
run_cmd "4G / ModemManager Summary" "systemctl status ModemManager --no-pager -l 2>/dev/null || true; mmcli -L 2>/dev/null || true"

MODEM_PATH="$(mmcli -L 2>/dev/null | sed -n 's#.*\(/org/freedesktop/ModemManager1/Modem/[0-9]\+\).*#\1#p' | head -n 1)"
if [[ -n "${MODEM_PATH:-}" ]]; then
  run_cmd "4G / Modem Details ($MODEM_PATH)" "mmcli -m '$MODEM_PATH' 2>/dev/null || mmcli -m 0 2>/dev/null || true"
fi

run_cmd "PiSailBox Service Status" "systemctl status pisailbox --no-pager -l 2>/dev/null || true"
run_cmd "PiSailBox Service Unit" "cat /etc/systemd/system/pisailbox.service 2>/dev/null || cat /lib/systemd/system/pisailbox.service 2>/dev/null || true"
run_cmd "PiSailBox Install Folder" "ls -lah /opt/pisailbox 2>/dev/null || true"
run_cmd "PiSailBox Runtime Data Folder" "ls -lah \"$TARGET_HOME/pisailbox_data\" 2>/dev/null || true; ls -lah \"$TARGET_HOME/pisailbox_data/photos\" 2>/dev/null || true; ls -lah \"$TARGET_HOME/pisailbox_data/videos\" 2>/dev/null || true"
run_cmd "PiSailBox Recent Logs (journalctl)" "journalctl -u pisailbox --no-pager -n 300 2>/dev/null || true"
run_cmd "PiSailBox App Log Tail" "tail -n 300 \"$TARGET_HOME/pisailbox_data/pisailbox.log\" 2>/dev/null || true"
run_cmd "Relevant Running Processes" "ps aux | grep -E 'pisailbox|python3|ModemManager|NetworkManager|mmcli' | grep -v grep || true"
run_cmd "Python Environment" "python3 -V 2>/dev/null || true; python3 -m pip -V 2>/dev/null || true; python3 -m pip show requests pyserial picamera2 2>/dev/null || true"

{
  echo
  echo "================================================================"
  echo "Done"
  echo "================================================================"
  echo "Debug report created:"
  echo "$OUT_FILE"
} >> "$OUT_FILE"

echo "Debug report created: $OUT_FILE"
echo "Share this file content for troubleshooting."
