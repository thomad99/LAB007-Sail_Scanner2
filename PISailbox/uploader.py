"""
Handles all HTTP communication with the Love Sailing server.
Queues failed uploads in SQLite for retry when network returns.
"""

import os
import json
import sqlite3
import threading
import time
import logging
import datetime

import requests

log = logging.getLogger(__name__)

RETRY_INTERVAL = 30   # seconds between retry attempts
REQUEST_TIMEOUT = 20  # seconds


class Uploader:
    """
    Uploads GPS points and photos to the server.
    Failed requests are queued in a local SQLite database.
    """

    def __init__(self, server_url, device_id, queue_db_path):
        self.server_url = server_url.rstrip("/")
        self.device_id  = device_id
        self.db_path    = queue_db_path
        self._lock      = threading.Lock()
        self._track_id  = None  # active server-side track id
        self._init_db()

    # ── SQLite queue ──────────────────────────────────────────────────────────

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS gps_queue (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload   TEXT    NOT NULL,
                    attempts  INTEGER NOT NULL DEFAULT 0,
                    created   TEXT    NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS photo_queue (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    filepath  TEXT    NOT NULL,
                    meta      TEXT    NOT NULL,
                    attempts  INTEGER NOT NULL DEFAULT 0,
                    created   TEXT    NOT NULL
                )
            """)
            db.commit()

    def _db(self):
        return sqlite3.connect(self.db_path)

    # ── Device registration ───────────────────────────────────────────────────

    @staticmethod
    def _get_all_ips():
        """
        Return a dict of {interface_name: ip_address} for all active non-loopback
        interfaces (WiFi, Ethernet, 4G modem, USB, etc.).
        """
        import subprocess, re
        ips = {}
        try:
            out = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=5)
            current = None
            for line in out.splitlines():
                m = re.match(r'^\d+: (\S+):', line)
                if m:
                    current = m.group(1).rstrip(':')
                ip_m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', line)
                if ip_m and current and current != 'lo':
                    ips[current] = ip_m.group(1)
        except Exception:
            pass
        return ips

    def register(self, os_info=None):
        """Register this device with the server and return its config dict."""
        import platform
        if os_info is None:
            os_info = platform.platform()

        ip_addresses = self._get_all_ips()

        payload = {
            "device_id":    self.device_id,
            "name":         self.device_id,
            "ip_addresses": ip_addresses,
            "os_info":      os_info,
        }
        try:
            resp = requests.post(
                f"{self.server_url}/api/pi/register",
                json=payload, timeout=REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            data = resp.json()
            log.info(f"Registered with server. Config: {data.get('config')}")
            return data.get("config", {})
        except Exception as e:
            log.warning(f"Registration failed: {e}")
            return {}

    def fetch_config(self):
        """Poll server for latest config. Returns dict or None."""
        try:
            resp = requests.get(
                f"{self.server_url}/api/pi/devices/{self.device_id}/config",
                timeout=REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.debug(f"Config fetch failed: {e}")
            return None

    # ── Track management ──────────────────────────────────────────────────────

    def start_track(self, name=None):
        """Create a new GPS track on the server. Returns track id or None."""
        if name is None:
            name = f"{self.device_id} — {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC"
        try:
            resp = requests.post(
                f"{self.server_url}/api/tracks",
                json={"name": name, "device_name": self.device_id},
                timeout=REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            self._track_id = resp.json()["id"]
            log.info(f"Track started: id={self._track_id}")
            return self._track_id
        except Exception as e:
            log.warning(f"Failed to start track: {e}")
            return None

    def stop_track(self):
        """Stop the current track on the server."""
        if not self._track_id:
            return
        try:
            requests.patch(
                f"{self.server_url}/api/tracks/{self._track_id}/stop",
                timeout=REQUEST_TIMEOUT
            )
            log.info(f"Track {self._track_id} stopped")
        except Exception as e:
            log.warning(f"Failed to stop track: {e}")
        self._track_id = None

    # ── GPS point upload ──────────────────────────────────────────────────────

    def upload_gps_point(self, fix):
        """Upload one GPS fix. Queues if upload fails."""
        if not self._track_id:
            log.debug("No active track, skipping GPS point")
            return

        payload = {
            "lat":      fix.lat,
            "lng":      fix.lng,
            "accuracy": fix.accuracy,
            "altitude": fix.altitude,
            "speed":    fix.speed,
            "heading":  fix.heading,
        }
        success = self._post_gps(payload)
        if not success:
            self._queue_gps(payload)

    def _post_gps(self, payload):
        try:
            resp = requests.post(
                f"{self.server_url}/api/tracks/{self._track_id}/points",
                json=payload, timeout=REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            return True
        except Exception as e:
            log.debug(f"GPS upload failed: {e}")
            return False

    def _queue_gps(self, payload):
        with self._db() as db:
            db.execute(
                "INSERT INTO gps_queue (payload, created) VALUES (?, ?)",
                (json.dumps(payload), datetime.datetime.utcnow().isoformat())
            )

    def flush_gps_queue(self):
        """Retry any queued GPS points."""
        if not self._track_id:
            return
        with self._db() as db:
            rows = db.execute(
                "SELECT id, payload FROM gps_queue WHERE attempts < 10 ORDER BY id LIMIT 50"
            ).fetchall()
        for row_id, payload_str in rows:
            payload = json.loads(payload_str)
            if self._post_gps(payload):
                with self._db() as db:
                    db.execute("DELETE FROM gps_queue WHERE id=?", (row_id,))
            else:
                with self._db() as db:
                    db.execute("UPDATE gps_queue SET attempts=attempts+1 WHERE id=?", (row_id,))

    # ── Photo upload ──────────────────────────────────────────────────────────

    def upload_photos(self, photo_list):
        """
        Upload a batch of photos.
        photo_list: list of (filepath, gps_fix_or_None)
        """
        if not photo_list:
            return

        files  = []
        metas  = []
        opened = []

        for fpath, fix in photo_list:
            if not os.path.exists(fpath):
                continue
            f = open(fpath, "rb")
            opened.append(f)
            files.append(("photos", (os.path.basename(fpath), f, "image/jpeg")))
            meta = {
                "captured_at": datetime.datetime.utcfromtimestamp(
                    os.path.getmtime(fpath)).isoformat() + "Z",
                "lat": fix.lat if fix else None,
                "lng": fix.lng if fix else None,
            }
            metas.append(meta)

        if not files:
            return

        try:
            resp = requests.post(
                f"{self.server_url}/api/pi/devices/{self.device_id}/photos",
                files=files,
                data={"meta": json.dumps(metas)},
                timeout=60
            )
            resp.raise_for_status()
            result = resp.json()
            log.info(f"Uploaded {result.get('saved',0)} photos")

            # Delete local files after successful upload
            for fpath, _ in photo_list:
                try:
                    os.remove(fpath)
                except Exception:
                    pass
        except Exception as e:
            log.warning(f"Photo batch upload failed: {e}")
            # Queue for retry
            for fpath, fix in photo_list:
                meta = {
                    "lat": fix.lat if fix else None,
                    "lng": fix.lng if fix else None,
                }
                with self._db() as db:
                    db.execute(
                        "INSERT INTO photo_queue (filepath, meta, created) VALUES (?,?,?)",
                        (fpath, json.dumps(meta), datetime.datetime.utcnow().isoformat())
                    )
        finally:
            for f in opened:
                try: f.close()
                except Exception: pass

    def report_sim_status(self, status):
        """Send SIM/modem status dict to the server."""
        try:
            requests.post(
                f"{self.server_url}/api/pi/devices/{self.device_id}/sim-status",
                json=status, timeout=REQUEST_TIMEOUT
            )
        except Exception as e:
            log.debug(f"SIM status upload failed: {e}")

    def flush_photo_queue(self):
        """Retry any queued photos."""
        with self._db() as db:
            rows = db.execute(
                "SELECT id, filepath, meta FROM photo_queue WHERE attempts < 5 LIMIT 20"
            ).fetchall()
        if not rows:
            return

        batch = []
        for row_id, fpath, meta_str in rows:
            meta = json.loads(meta_str)

            class _MockFix:
                lat = meta.get("lat")
                lng = meta.get("lng")

            if os.path.exists(fpath):
                batch.append((fpath, _MockFix()))

        if batch:
            self.upload_photos(batch)
            for row_id, fpath, _ in rows:
                if not os.path.exists(fpath):
                    with self._db() as db:
                        db.execute("DELETE FROM photo_queue WHERE id=?", (row_id,))
                else:
                    with self._db() as db:
                        db.execute("UPDATE photo_queue SET attempts=attempts+1 WHERE id=?", (row_id,))
