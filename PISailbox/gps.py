"""
GPS reader for SIMCOM SIM7600G-H via UART (ttyAMA0).

This module uses AT+CGPS / AT+CGPSINFO command set
(NOT AT+CGNSPWR / AT+CGNSINF which return ERROR on this firmware).

+CGPSINFO response format when fix acquired:
  +CGPSINFO: DDMM.MMMM,N/S,DDDMM.MMMM,E/W,DDMMYY,HHMMSS.S,alt,speed_kmh,course
"""

import datetime
import os
import serial
import threading
import time
import logging
import re

import config as cfg

log = logging.getLogger(__name__)

AT_OK    = "OK"
AT_ERROR = "ERROR"


class GPSFix:
    def __init__(self, lat, lng, altitude=None, speed_ms=None,
                 course=None, accuracy=None, utc=None):
        self.lat      = lat
        self.lng      = lng
        self.altitude = altitude
        self.speed    = speed_ms   # m/s
        self.heading  = course
        self.accuracy = accuracy
        self.utc      = utc

    def is_valid(self):
        return self.lat is not None and self.lng is not None

    def __repr__(self):
        return f"GPSFix(lat={self.lat:.6f}, lng={self.lng:.6f}, spd={self.speed})"


class GPSReader:
    """
    Reads GPS position from SIM7600G-H via UART AT commands.
    Uses AT+CGPS / AT+CGPSINFO command set.
    """

    def __init__(self, port, baud=115200):
        self.port          = port
        self.baud          = baud
        self.ser           = None
        # RLock: _open / pause / resume / _send_at must not race; same thread re-enters during init.
        self.lock          = threading.RLock()
        self.current_fix   = None
        self._running      = False
        self.gps_engine_on = False
        self.fix_count     = 0
        self.no_fix_count  = 0
        self.last_fix_at_iso = None   # UTC ISO when we last read a valid fix from the modem
        self.last_error    = None
        self._recent_errors = []   # up to 10 recent error strings

    # ── Serial helpers ────────────────────────────────────────────────────────

    @property
    def is_ready(self):
        return self.ser is not None and self.ser.is_open

    def _close_unlocked(self):
        try:
            if self.ser and self.ser.is_open:
                self.ser.close()
        except Exception:
            pass
        self.ser = None

    def _open(self):
        with self.lock:
            if self.ser and self.ser.is_open:
                return
            self.ser = serial.Serial(
                self.port, self.baud,
                timeout=3, write_timeout=3,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                rtscts=False,
                dsrdtr=False
            )
            log.info(f"Opened serial port {self.port}")

    def _close(self):
        with self.lock:
            self._close_unlocked()

    def _send_at(self, cmd, wait_s=1.5):
        """Send AT command and return response. Returns '' if port not ready."""
        with self.lock:
            if not self.ser or not self.ser.is_open:
                log.debug(f"AT skipped (port not open): {cmd}")
                return ""
            try:
                self.ser.reset_input_buffer()
                self.ser.write((cmd + "\r\n").encode())
                time.sleep(wait_s)
                raw = self.ser.read_all().decode(errors="ignore")
                return raw.strip()
            except Exception as e:
                msg = f"AT command failed ({cmd}): {e}"
                log.warning(msg)
                self.last_error = msg
                self._recent_errors.append(msg)
                if len(self._recent_errors) > 10:
                    self._recent_errors.pop(0)
                return ""

    # ── GPS init ──────────────────────────────────────────────────────────────

    def _init_gps(self):
        # Cold boot: modem UART stack may need longer than a running system
        time.sleep(max(2.0, cfg.GPS_AT_INIT_SLEEP))

        # Confirm modem alive — retry with backoff (cold boot can need many tries)
        max_at = int(os.environ.get("PISAILBOX_GPS_AT_RETRIES", "12"))
        for attempt in range(max_at):
            resp = self._send_at("AT", wait_s=1.5)
            if AT_OK in resp:
                break
            log.warning(f"AT attempt {attempt+1}/{max_at}: no OK (got: {repr(resp[:40])})")
            time.sleep(min(2 + attempt // 3, 6))
        else:
            msg = f"Modem not responding to AT after {max_at} attempts"
            log.error(msg)
            self.last_error = msg
            self._recent_errors.append(msg)
            if len(self._recent_errors) > 10:
                self._recent_errors.pop(0)
            return False

        # Echo off
        self._send_at("ATE0", wait_s=0.5)

        # Enable GPS using AT+CGPS command set (SIM7600G-H firmware)
        resp = self._send_at("AT+CGPS=1", wait_s=2.0)
        if AT_OK in resp or "already" in resp.lower():
            log.info("GPS enabled via AT+CGPS=1")
        else:
            # May already be running — not fatal
            log.warning(f"AT+CGPS=1 response: {repr(resp[:60])}")

        time.sleep(2)
        log.info("GNSS engine powered on")
        self.gps_engine_on = True
        return True

    def recover_gnss(self):
        """
        Soft-reset GNSS without tearing down the whole process (same idea as app restart).
        Call when tracking but CGPSINFO never returns a fix after a long time.
        """
        log.warning("GPS: recover_gnss — cycling AT+CGPS off/on")
        self._send_at("AT+CGPS=0", wait_s=1.5)
        time.sleep(2.5)
        resp = self._send_at("AT+CGPS=1", wait_s=2.5)
        if resp and "ERROR" in resp and AT_OK not in resp:
            log.warning(f"GPS recover AT+CGPS=1: {repr(resp[:80])}")
        else:
            self.gps_engine_on = True
            log.info("GPS: GNSS engine cycled")

    # ── Parse +CGPSINFO ───────────────────────────────────────────────────────

    @staticmethod
    def _nmea_to_decimal(value, direction):
        """
        Convert NMEA DDMM.MMMM or DDDMM.MMMM + N/S/E/W to decimal degrees.
        """
        if not value:
            return None
        try:
            f = float(value)
            # degrees are the integer part before last 2 digits before decimal
            deg = int(f / 100)
            minutes = f - deg * 100
            decimal = deg + minutes / 60.0
            if direction in ('S', 'W'):
                decimal = -decimal
            return decimal
        except (ValueError, TypeError):
            return None

    def _parse_cgpsinfo(self, resp):
        """
        Parse AT+CGPSINFO response.
        +CGPSINFO: lat,N/S,lon,E/W,date,time,alt,speed_kmh,course
        Returns GPSFix or None.
        """
        try:
            prefix = "+CGPSINFO:"
            idx = resp.find(prefix)
            if idx < 0:
                return None
            data = resp[idx + len(prefix):].strip().split(",")
            if len(data) < 8:
                return None

            lat_raw, ns, lon_raw, ew = data[0], data[1], data[2], data[3]
            utc_time  = data[5].strip() if len(data) > 5 else None
            alt_raw   = data[6].strip() if len(data) > 6 else None
            spd_raw   = data[7].strip() if len(data) > 7 else None
            course_raw= data[8].strip() if len(data) > 8 else None

            # Empty fields = no fix
            if not lat_raw.strip() or not lon_raw.strip():
                return None

            lat = self._nmea_to_decimal(lat_raw.strip(), ns.strip())
            lng = self._nmea_to_decimal(lon_raw.strip(), ew.strip())
            if lat is None or lng is None:
                return None

            alt    = float(alt_raw)   if alt_raw    else None
            spd_ms = float(spd_raw) / 3.6 if spd_raw else None   # km/h → m/s
            try:
                course = float(course_raw) if course_raw else None
            except (ValueError, TypeError):
                course = None   # course field sometimes contains '\r\nOK'

            return GPSFix(lat, lng,
                          altitude=alt,
                          speed_ms=spd_ms,
                          course=course,
                          utc=utc_time)
        except Exception as e:
            log.debug(f"CGPSINFO parse error: {e} | raw={resp[:80]}")
            return None

    # ── Public interface ──────────────────────────────────────────────────────

    def get_fix(self):
        """Query GPS and return current fix, or None if no fix yet."""
        resp = self._send_at("AT+CGPSINFO", wait_s=2.0)
        fix  = self._parse_cgpsinfo(resp)
        if fix:
            self.current_fix = fix
            self.fix_count += 1
            self.last_fix_at_iso = datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        else:
            self.no_fix_count += 1
        return fix

    def start(self, retry_interval=5):
        """Open serial port, init GPS, retry on failure."""
        self._running = True
        deadline = time.time() + cfg.GPS_WAIT_PORT_TIMEOUT
        while self._running and not os.path.exists(self.port):
            if time.time() > deadline:
                log.error(
                    f"GPS serial {self.port} not present after {cfg.GPS_WAIT_PORT_TIMEOUT}s "
                    "(check HAT power / UART enabled / ModemManager not holding the port)"
                )
                time.sleep(retry_interval)
                deadline = time.time() + cfg.GPS_WAIT_PORT_TIMEOUT
                continue
            log.warning(f"GPS: waiting for serial device {self.port}…")
            time.sleep(2)
        while self._running:
            try:
                self._open()
                if self._init_gps():
                    log.info("GPS ready")
                    return True
                else:
                    log.warning("GPS init failed, retrying…")
                    self._close()
                    time.sleep(retry_interval)
            except serial.SerialException as e:
                log.error(f"Serial open failed: {e} — retrying in {retry_interval}s")
                self._close()
                time.sleep(retry_interval)
        return False

    def pause(self):
        """Temporarily close serial port so PPP can use it."""
        log.info("GPS: pausing serial port for PPP")
        self._close()

    def resume(self):
        """Reopen serial port after PPP has finished and re-enable GPS engine."""
        log.info("GPS: resuming serial port after PPP")
        try:
            self._open()
            self._send_at("ATE0", wait_s=0.5)   # echo off

            # GPS engine was stopped by _modem_reset before PPP; restart it now
            resp = self._send_at("AT+CGPS=1", wait_s=2.0)
            if resp and 'ERROR' in resp:
                log.warning(f"GPS re-enable after PPP got error: {resp}")
            else:
                self.gps_engine_on = True
                log.info("GPS: engine re-enabled after PPP")

            log.info("GPS: serial port resumed")
        except Exception as e:
            log.warning(f"GPS resume failed: {e} — will retry on next poll")

    def stop(self):
        self._running = False
        self.gps_engine_on = False
        try:
            self._send_at("AT+CGPS=0", wait_s=1.0)  # power off GPS
        except Exception:
            pass
        self._close()
        log.info("GPS stopped")
