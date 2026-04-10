"""
SIM7600 AT-command HTTP uploader.

Uploads queued GPS points directly through the modem's built-in HTTP stack,
bypassing PPP entirely.  Works because the modem already has an active PDP
context (AT+CGACT: 1,1) with a live internet connection.

Flow
----
1. gps_reader.pause()  — releases /dev/ttyAMA0
2. sim_http.flush_via_at_http(...)  — opens port, does AT+HTTP POST, closes port
3. gps_reader.resume() — reclaims the port and restarts GPS engine
"""

import json
import re
import sqlite3
import time
import logging

import config as cfg

log = logging.getLogger(__name__)

# How long to wait for +HTTPACTION response (server round-trip)
HTTP_TIMEOUT = 30


def _send(s, cmd, wait=1.0):
    """Write an AT command and return the response text."""
    s.reset_input_buffer()
    if isinstance(cmd, str):
        cmd = (cmd + '\r\n').encode()
    s.write(cmd)
    time.sleep(wait)
    return s.read_all().decode(errors='ignore')


def _at_post(s, url, body_dict):
    """
    POST body_dict as JSON to url using AT+HTTP commands.
    Returns the HTTP status code (int), or raises RuntimeError on failure.
    """
    body_bytes = json.dumps(body_dict).encode()

    # Clean up any previous HTTP session
    _send(s, 'AT+HTTPTERM', 0.5)

    # Enable SSL for https:// URLs
    if url.lower().startswith('https'):
        _send(s, 'AT+HTTPSSL=1', 1.0)
    else:
        _send(s, 'AT+HTTPSSL=0', 0.5)

    resp = _send(s, 'AT+HTTPINIT', 2.0)
    if 'ERROR' in resp:
        raise RuntimeError(f'HTTPINIT failed: {resp.strip()!r}')

    _send(s, f'AT+HTTPPARA="URL","{url}"', 1.0)
    _send(s, 'AT+HTTPPARA="CONTENT","application/json"', 0.5)

    # Upload the POST body
    resp = _send(s, f'AT+HTTPDATA={len(body_bytes)},10000', 2.0)
    if 'DOWNLOAD' not in resp:
        raise RuntimeError(f'HTTPDATA: expected DOWNLOAD prompt, got: {resp.strip()!r}')

    s.write(body_bytes)
    time.sleep(2.0)
    s.read_all()   # consume any echo

    # Trigger POST and wait for +HTTPACTION response
    s.reset_input_buffer()
    s.write(b'AT+HTTPACTION=1\r\n')
    deadline = time.time() + HTTP_TIMEOUT
    buf = ''
    while time.time() < deadline:
        time.sleep(1)
        buf += s.read_all().decode(errors='ignore')
        if '+HTTPACTION' in buf:
            break

    _send(s, 'AT+HTTPTERM', 0.5)

    m = re.search(r'\+HTTPACTION:\s*1,(\d+),(\d+)', buf)
    if not m:
        raise RuntimeError(f'No +HTTPACTION in response: {buf[:200]!r}')

    return int(m.group(1))   # HTTP status code


def flush_via_at_http(serial_port, baud_rate, server_url, track_id, db_path):
    """
    Read GPS points from the local SQLite queue and upload them to the server
    using the modem's built-in HTTP stack (no PPP required).

    Returns the number of points successfully uploaded.
    """
    if not track_id:
        log.warning('SIM-HTTP: no active track — skipping')
        return 0

    # ── Read queued points ───────────────────────────────────────────────────
    try:
        with sqlite3.connect(db_path) as db:
            rows = db.execute(
                "SELECT id, payload FROM gps_queue WHERE attempts < ? ORDER BY id LIMIT 100",
                (cfg.GPS_QUEUE_MAX_ATTEMPTS,),
            ).fetchall()
    except Exception as e:
        log.warning(f'SIM-HTTP: cannot read queue: {e}')
        return 0

    if not rows:
        log.info('SIM-HTTP: queue is empty')
        return 0

    # ── Open serial port ─────────────────────────────────────────────────────
    try:
        import serial as _serial
        s = _serial.Serial(serial_port, baud_rate, timeout=3,
                           rtscts=False, dsrdtr=False)
        time.sleep(0.5)
        s.reset_input_buffer()
        _send(s, 'ATE0', 0.5)   # echo off
    except Exception as e:
        log.warning(f'SIM-HTTP: cannot open serial port: {e}')
        return 0

    # ── Upload each point ────────────────────────────────────────────────────
    url = f'{server_url}/api/tracks/{track_id}/points'
    sent = 0
    try:
        for row_id, payload_str in rows:
            try:
                payload = json.loads(payload_str)
                status  = _at_post(s, url, payload)
                if status in (200, 201):
                    with sqlite3.connect(db_path) as db:
                        db.execute('DELETE FROM gps_queue WHERE id=?', (row_id,))
                    sent += 1
                    log.debug(f'SIM-HTTP: point {row_id} → HTTP {status}')
                else:
                    log.warning(f'SIM-HTTP: point {row_id} → HTTP {status} — stopping')
                    with sqlite3.connect(db_path) as db:
                        db.execute('UPDATE gps_queue SET attempts=attempts+1 WHERE id=?', (row_id,))
                    break
            except Exception as e:
                log.warning(f'SIM-HTTP: point {row_id} upload error: {e}')
                with sqlite3.connect(db_path) as db:
                    db.execute('UPDATE gps_queue SET attempts=attempts+1 WHERE id=?', (row_id,))
                break  # network error — stop and try next cycle
    finally:
        try:
            s.close()
        except Exception:
            pass

    if sent:
        log.info(f'SIM-HTTP: uploaded {sent} point(s) via SIM to track {track_id}')
    return sent
