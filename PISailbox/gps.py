"""
GPS reader for Waveshare SIM7600G-H 4G HAT.
Uses AT commands over serial to query the GNSS engine.
"""

import serial
import threading
import time
import logging

log = logging.getLogger(__name__)

# AT command responses
AT_OK    = "OK"
AT_ERROR = "ERROR"

class GPSFix:
    """Holds a single GPS fix."""
    def __init__(self, lat, lng, altitude=None, speed_ms=None,
                 course=None, accuracy=None, utc=None):
        self.lat       = lat
        self.lng       = lng
        self.altitude  = altitude
        self.speed     = speed_ms   # m/s
        self.heading   = course
        self.accuracy  = accuracy
        self.utc       = utc        # datetime string from device

    def is_valid(self):
        return self.lat is not None and self.lng is not None

    def __repr__(self):
        return f"GPSFix(lat={self.lat:.6f}, lng={self.lng:.6f}, spd={self.speed})"


class GPSReader:
    """
    Reads GPS position from SIM7600G-H via serial AT commands.
    Call start() once; then read .current_fix at any time.
    """

    def __init__(self, port, baud=115200):
        self.port     = port
        self.baud     = baud
        self.ser      = None
        self.lock     = threading.Lock()
        self.current_fix = None
        self._running = False

    # ── Serial helpers ────────────────────────────────────────────────────────

    def _open(self):
        self.ser = serial.Serial(
            self.port, self.baud,
            timeout=3, write_timeout=3,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE
        )
        log.info(f"Opened serial port {self.port}")

    def _send_at(self, cmd, wait_s=1.5):
        """Send AT command and return response string."""
        with self.lock:
            try:
                self.ser.reset_input_buffer()
                self.ser.write((cmd + "\r\n").encode())
                time.sleep(wait_s)
                raw = self.ser.read_all().decode(errors="ignore")
                return raw.strip()
            except Exception as e:
                log.warning(f"AT command failed ({cmd}): {e}")
                return ""

    # ── Initialise GNSS engine ────────────────────────────────────────────────

    def _init_gps(self):
        # Check modem is alive
        resp = self._send_at("AT")
        if AT_OK not in resp:
            log.error("Modem not responding to AT")
            return False

        # Power on GNSS
        self._send_at("AT+CGNSPWR=1")
        time.sleep(2)

        # Set NMEA output rate (optional but helps lock faster)
        self._send_at("AT+CGNSSEQ=\"RMC\"")

        log.info("GNSS engine powered on")
        return True

    # ── Parse +CGNSINF response ───────────────────────────────────────────────

    def _parse_cgnsinf(self, resp):
        """
        Parse AT+CGNSINF response.
        Format: +CGNSINF: run,fix,utc,lat,lon,alt,spd_kmh,course,fix_mode,...
        """
        try:
            prefix = "+CGNSINF:"
            idx = resp.find(prefix)
            if idx < 0:
                return None
            data = resp[idx + len(prefix):].strip().split(",")
            if len(data) < 6:
                return None

            gnss_run  = data[0].strip()
            fix_status = data[1].strip()

            if gnss_run != "1" or fix_status != "1":
                return None  # no fix yet

            utc  = data[2].strip()
            lat  = float(data[3]) if data[3] else None
            lng  = float(data[4]) if data[4] else None
            alt  = float(data[5]) if data[5] else None
            spd_kmh = float(data[6]) if data[6] else None
            course  = float(data[7]) if len(data) > 7 and data[7] else None

            if lat is None or lng is None:
                return None

            # Convert speed km/h → m/s
            spd_ms = spd_kmh / 3.6 if spd_kmh is not None else None

            return GPSFix(lat, lng,
                          altitude=alt,
                          speed_ms=spd_ms,
                          course=course,
                          utc=utc)
        except Exception as e:
            log.debug(f"CGNSINF parse error: {e} | raw={resp[:80]}")
            return None

    # ── Public interface ──────────────────────────────────────────────────────

    def get_fix(self):
        """Query and return current GPS fix (or None if no fix)."""
        resp = self._send_at("AT+CGNSINF", wait_s=1.0)
        fix = self._parse_cgnsinf(resp)
        if fix:
            self.current_fix = fix
        return fix

    def start(self, retry_interval=5):
        """Open serial port, init GNSS, keep retrying on failure."""
        self._running = True
        while self._running:
            try:
                self._open()
                if self._init_gps():
                    log.info("GPS ready")
                    return True
                else:
                    log.warning("GPS init failed, retrying…")
                    time.sleep(retry_interval)
            except serial.SerialException as e:
                log.error(f"Serial open failed: {e} — retrying in {retry_interval}s")
                time.sleep(retry_interval)
        return False

    def stop(self):
        self._running = False
        try:
            self._send_at("AT+CGNSPWR=0")  # power off GNSS
        except Exception:
            pass
        if self.ser and self.ser.is_open:
            self.ser.close()
        log.info("GPS stopped")
