"""
PiSailBox configuration.
Edit SERVER_URL before installing, then run install.sh.
All other values are overridden at runtime by the server config.
"""

import os
import socket

# ── Server connection ─────────────────────────────────────────────────────────
SERVER_URL = os.environ.get("PISAILBOX_SERVER", "https://lovesailing.ai")

# ── Device identity ───────────────────────────────────────────────────────────
# Reads hostname; override with PISAILBOX_DEVICE_ID env var if needed.
DEVICE_ID = os.environ.get("PISAILBOX_DEVICE_ID", socket.gethostname())
DEVICE_NAME = os.environ.get("PISAILBOX_NAME", DEVICE_ID)

# ── SIM7600 serial port ───────────────────────────────────────────────────────
# The SIM7600G-H HAT typically appears as /dev/ttyUSB2 for AT commands.
# Change to /dev/ttyUSB1 or /dev/ttyS0 if GPS is not found.
GPS_SERIAL_PORT = os.environ.get("GPS_PORT", "/dev/ttyUSB2")
GPS_BAUD_RATE   = 115200

# ── Local storage ─────────────────────────────────────────────────────────────
DATA_DIR    = os.path.expanduser("~/pisailbox_data")
PHOTOS_DIR  = os.path.join(DATA_DIR, "photos")
VIDEOS_DIR  = os.path.join(DATA_DIR, "videos")
QUEUE_DB    = os.path.join(DATA_DIR, "queue.sqlite")

# ── Defaults (overridden by server config) ────────────────────────────────────
DEFAULT_CONFIG = {
    "gps_poll_seconds":              10,
    "camera_enabled":                False,
    "photo_interval_seconds":        30,
    "photo_session_minutes":         60,
    "photo_upload_interval_minutes": 5,
    "video_enabled":                 False,
    "video_interval_minutes":        10,
    "video_duration_seconds":        60,
}

# Config is polled from server every N seconds
CONFIG_POLL_SECONDS = 30
