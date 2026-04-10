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

# Cold-boot: UART/modem may not be ready when systemd starts the app (even with ExecStartPre sleep).
MODEM_SETTLE_SECONDS = float(os.environ.get("PISAILBOX_MODEM_SETTLE", "18"))
# After GPS engine is enabled, delay before APN AT sequence — avoids PDP churn during GNSS first lock.
APN_APPLY_DELAY_SECONDS = float(os.environ.get("PISAILBOX_APN_DELAY", "30"))
# Wait for serial device node to appear (seconds).
GPS_WAIT_PORT_TIMEOUT = int(os.environ.get("PISAILBOX_GPS_WAIT_PORT", "120"))
# Extra pause inside AT+CGPS init before first AT (modem firmware boot).
GPS_AT_INIT_SLEEP = float(os.environ.get("PISAILBOX_GPS_AT_INIT_SLEEP", "4"))

# ── Local storage ─────────────────────────────────────────────────────────────
DATA_DIR    = os.path.expanduser("~/pisailbox_data")
PHOTOS_DIR  = os.path.join(DATA_DIR, "photos")
VIDEOS_DIR  = os.path.join(DATA_DIR, "videos")
QUEUE_DB      = os.path.join(DATA_DIR, "queue.sqlite")
TRACK_ID_FILE = os.path.join(DATA_DIR, "current_track_id")   # persists track across WiFi loss

# GPS queue: rows are retried until uploaded; this caps runaway rows (set high for “keep until link works”).
GPS_QUEUE_MAX_ATTEMPTS = int(os.environ.get("PISAILBOX_GPS_QUEUE_MAX_ATTEMPTS", "10000"))

# Append-only backup of every queued GPS fix (in addition to SQLite). Disable with PISAILBOX_GPS_JSONL=0.
GPS_POINTS_JSONL = os.path.join(DATA_DIR, "gps_points.jsonl")
GPS_POINTS_JSONL_ENABLED = os.environ.get("PISAILBOX_GPS_JSONL", "1").strip().lower() not in ("0", "false", "no")

# ── Defaults (overridden by server config) ────────────────────────────────────
DEFAULT_CONFIG = {
    "gps_poll_seconds":              10,   # how often to read GPS (seconds)
    "gps_upload_interval_seconds":   60,   # how often to upload batched points to server
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
