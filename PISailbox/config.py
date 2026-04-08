"""
PiSailBox configuration.
Edit SERVER_URL before installing, then run install.sh.
All other values are overridden at runtime by the server config.
"""

import os
import socket

# ── Server connection ─────────────────────────────────────────────────────────
SERVER_URL = os.environ.get("PISAILBOX_SERVER", "https://lovesailing.ai")

# SIM AT-HTTP uploads must use plain HTTP — the SIM7600G_V2.0.2 firmware has no
# HTTPS support via AT commands (AT+HTTPSSL is not implemented).
# Requires "Force HTTPS" to be DISABLED in the Render.com service settings.
SIM_SERVER_URL = os.environ.get("PISAILBOX_SIM_SERVER",
                                SERVER_URL.replace("https://", "http://"))

# ── Device identity ───────────────────────────────────────────────────────────
# Reads hostname; override with PISAILBOX_DEVICE_ID env var if needed.
DEVICE_ID = os.environ.get("PISAILBOX_DEVICE_ID", socket.gethostname())
DEVICE_NAME = os.environ.get("PISAILBOX_NAME", DEVICE_ID)

# ── SIM7600 serial port ───────────────────────────────────────────────────────
# On this Pi the HAT is wired via GPIO UART (/dev/ttyAMA0).
# Override with GPS_PORT env var if the port is different on another unit.
GPS_SERIAL_PORT = os.environ.get("GPS_PORT", "/dev/ttyAMA0")
GPS_BAUD_RATE   = 115200

# ── Local storage ─────────────────────────────────────────────────────────────
DATA_DIR    = os.path.expanduser("~/pisailbox_data")
PHOTOS_DIR  = os.path.join(DATA_DIR, "photos")
VIDEOS_DIR  = os.path.join(DATA_DIR, "videos")
QUEUE_DB      = os.path.join(DATA_DIR, "queue.sqlite")
TRACK_ID_FILE = os.path.join(DATA_DIR, "current_track_id")   # persists track across WiFi loss

# ── Defaults (overridden by server config) ────────────────────────────────────
DEFAULT_CONFIG = {
    "config_poll_interval_seconds":  30,   # how often to poll server for config + SIM MQTT upload batch
    "gps_poll_seconds":              10,   # how often to read GPS (seconds)
    "gps_upload_interval_seconds":   30,   # kept in sync with check-in; upload uses check-in interval
    "camera_enabled":                False,
    "photo_interval_seconds":        30,
    "photo_session_minutes":         60,
    "photo_upload_interval_minutes": 5,
    "video_enabled":                 False,
    "video_interval_minutes":        10,
    "video_duration_seconds":        60,
}

# Fallback if server config has no config_poll_interval_seconds yet
CONFIG_POLL_SECONDS = 30
