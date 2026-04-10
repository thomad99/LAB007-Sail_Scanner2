"""
SIM7600 AT-command MQTT manager.

Handles ALL SIM communication without WiFi:
  - Publishes GPS track points  →  pisailbox/{id}/gps
  - Publishes device status     →  pisailbox/{id}/status
  - Subscribes for config       ←  pisailbox/{id}/config  (retained)

The server publishes a retained config message whenever the user changes
settings or sends a command (start/stop track, capture photo, etc.) in
PiControl.  The Pi subscribes each MQTT cycle and picks up any changes
automatically, even with no WiFi.

Flow per cycle
--------------
1. gps_reader.pause()  — releases /dev/ttyAMA0
2. sim_mqtt.flush_via_mqtt(...)  — opens port, runs AT+CMQTT*, closes port
3. gps_reader.resume() — reclaims the port and restarts GPS engine

Return value
------------
flush_via_mqtt() returns a dict:
  {
    "sent":    int,          # GPS points published
    "config":  dict | None,  # config received from server (or None)
  }

Modem MQTT state
----------------
AT+CMQTTSTART / AT+CMQTTACCQ persist across modem power cycles.
Errors 23 (service already started) and 19 (client already exists) are harmless.

Broker
------
Uses broker.hivemq.com:1883 (free, public, plain TCP — no TLS needed).
Override with PISAILBOX_MQTT_BROKER env var.
"""

import json
import os
import re
import sqlite3
import time
import logging

import config as cfg

log = logging.getLogger(__name__)

BROKER_URL = os.environ.get("PISAILBOX_MQTT_BROKER", "tcp://broker.hivemq.com:1883")
KEEPALIVE  = 60
TOPIC_ROOT = "pisailbox"


# ── Low-level AT helpers ──────────────────────────────────────────────────────

def _send(s, cmd, wait=1.0):
    s.reset_input_buffer()
    if isinstance(cmd, str):
        cmd = (cmd + '\r\n').encode()
    s.write(cmd)
    time.sleep(wait)
    return s.read_all().decode(errors='ignore')


def _write_data(s, prompt_cmd, data_bytes):
    """Send AT+CMQTTTOPIC or AT+CMQTTPAYLOAD and write bytes after '>' prompt."""
    s.reset_input_buffer()
    s.write((prompt_cmd + '\r\n').encode())
    time.sleep(0.5)
    p = s.read_all().decode(errors='ignore')
    if '>' not in p:
        raise RuntimeError(f'{prompt_cmd!r} — no > prompt; got: {p.strip()!r}')
    s.write(data_bytes)
    time.sleep(0.5)
    s.read_all()


# ── Session management ────────────────────────────────────────────────────────

def _ensure_session(s, device_id):
    """Start MQTT service and acquire session 0.  Safe to call repeatedly."""
    resp = _send(s, 'AT+CMQTTSTART', 2.0)
    # error 23 = service already started — fine
    if 'ERROR' in resp and '+CMQTTSTART: 23' not in resp:
        raise RuntimeError(f'CMQTTSTART: {resp.strip()!r}')

    resp = _send(s, f'AT+CMQTTACCQ=0,"{device_id[:20]}"', 2.0)
    # error 19 = client already exists — fine
    if 'ERROR' in resp and '+CMQTTACCQ: 0,19' not in resp:
        raise RuntimeError(f'CMQTTACCQ: {resp.strip()!r}')


def _connect(s):
    _send(s, 'AT+CMQTTDISC=0,120', 3.0)   # ignored if already disconnected
    resp = _send(s, f'AT+CMQTTCONNECT=0,"{BROKER_URL}",{KEEPALIVE},1', 10.0)
    if '+CMQTTCONNECT: 0,0' not in resp:
        raise RuntimeError(f'MQTT connect: {resp.strip()!r}')


# ── Publish ───────────────────────────────────────────────────────────────────

def _publish_one(s, topic_bytes, payload_bytes):
    _write_data(s, f'AT+CMQTTTOPIC=0,{len(topic_bytes)}', topic_bytes)
    _write_data(s, f'AT+CMQTTPAYLOAD=0,{len(payload_bytes)}', payload_bytes)
    resp = _send(s, 'AT+CMQTTPUB=0,1,60', 10.0)
    if '+CMQTTPUB: 0,0' not in resp:
        raise RuntimeError(f'CMQTTPUB: {resp.strip()!r}')


# ── Subscribe + receive retained message ─────────────────────────────────────

def _subscribe_and_receive(s, topic_bytes, wait_s=3.0):
    """
    Subscribe to a topic and return the payload of the first received message
    (bytes), or None.

    Retained messages arrive within ~1 second of subscription.
    The URC pattern is:
      +CMQTTRXSTART: 0,<N>
      +CMQTTRXTOPIC: 0,<L>
      <topic>
      +CMQTTRXPAYLOAD: 0,<P>
      <payload>
      +CMQTTRXEND: 0
    """
    s.reset_input_buffer()
    s.write(f'AT+CMQTTSUB=0,{len(topic_bytes)},0\r\n'.encode())
    time.sleep(0.5)
    resp = s.read_all().decode(errors='ignore')

    if '>' not in resp:
        log.warning(f'CMQTTSUB: no > prompt for {topic_bytes.decode()!r}; got: {resp.strip()!r}')
        return None

    s.write(topic_bytes)

    # Wait for SUBACK + retained message URC
    time.sleep(wait_s)
    data = s.read_all().decode(errors='ignore')
    log.debug(f'CMQTTSUB raw response: {data!r}')

    # Extract payload between +CMQTTRXPAYLOAD header and +CMQTTRXEND
    m = re.search(r'\+CMQTTRXPAYLOAD:\s*\d+,\d+\r?\n(.*?)\r?\n\+CMQTTRXEND', data, re.DOTALL)
    if m:
        payload_str = m.group(1).strip()
        log.debug(f'CMQTTSUB received {len(payload_str)} bytes')
        return payload_str.encode()

    log.debug(f'CMQTTSUB: no retained message for {topic_bytes.decode()!r}')
    return None


# ── Main entry point ──────────────────────────────────────────────────────────

def flush_via_mqtt(serial_port, baud_rate, device_id, track_id, db_path,
                   status_payload=None):
    """
    Full MQTT management cycle:
      1. Subscribe to pisailbox/{device_id}/config — receive retained config/commands
      2. Publish GPS points from queue to pisailbox/{device_id}/gps
      3. Publish device status to pisailbox/{device_id}/status

    Parameters
    ----------
    track_id      : int | None  — active track id (may be None if not yet known)
    status_payload: dict | None — device status to publish (optional)

    Returns
    -------
    dict  {"sent": int, "config": dict | None}
    """
    result = {"sent": 0, "config": None}

    # Load GPS queue (publish even if track_id is None — server may provide one via config)
    try:
        with sqlite3.connect(db_path) as db:
            rows = db.execute(
                "SELECT id, payload FROM gps_queue WHERE attempts < ? ORDER BY id LIMIT 20",
                (cfg.GPS_QUEUE_MAX_ATTEMPTS,),
            ).fetchall()
    except Exception as e:
        log.warning(f'SIM-MQTT: cannot read queue: {e}')
        return result

    has_gps   = len(rows) > 0 and track_id is not None
    has_status = status_payload is not None
    config_topic = f'{TOPIC_ROOT}/{device_id}/config'.encode()
    gps_topic    = f'{TOPIC_ROOT}/{device_id}/gps'.encode()
    status_topic = f'{TOPIC_ROOT}/{device_id}/status'.encode()

    try:
        import serial as _serial
        s = _serial.Serial(serial_port, baud_rate, timeout=3, rtscts=False, dsrdtr=False)
        time.sleep(0.5)
        s.reset_input_buffer()
        _send(s, 'ATE0', 0.5)
    except Exception as e:
        log.warning(f'SIM-MQTT: cannot open serial port: {e}')
        return result

    try:
        _ensure_session(s, device_id)
        _connect(s)
        log.info('SIM-MQTT: connected to broker')

        # ── 1. Subscribe to config topic (retained — pick up any server changes) ──
        try:
            raw = _subscribe_and_receive(s, config_topic, wait_s=3.0)
            if raw:
                cfg = json.loads(raw.decode(errors='ignore'))
                result["config"] = cfg
                log.info(f'SIM-MQTT: received config from server (track={cfg.get("active_track_id")}, '
                         f'cmds={cfg.get("__commands", [])})')
        except Exception as e:
            log.warning(f'SIM-MQTT: config subscribe error: {e}')

        # ── 2. Publish GPS points ──────────────────────────────────────────────
        if has_gps:
            for row_id, payload_str in rows:
                try:
                    payload = json.loads(payload_str)
                    payload['track_id'] = track_id
                    payload_bytes = json.dumps(payload).encode()
                    _publish_one(s, gps_topic, payload_bytes)
                    with sqlite3.connect(db_path) as db:
                        db.execute('DELETE FROM gps_queue WHERE id=?', (row_id,))
                    result["sent"] += 1
                    log.debug(f'SIM-MQTT: GPS point {row_id} published')
                except Exception as e:
                    log.warning(f'SIM-MQTT: GPS point {row_id} error: {e}')
                    with sqlite3.connect(db_path) as db:
                        db.execute('UPDATE gps_queue SET attempts=attempts+1 WHERE id=?', (row_id,))
                    break
        elif rows and not track_id:
            log.info('SIM-MQTT: GPS points in queue but no track_id yet — will publish after config received')

        # ── 3. Publish device status ───────────────────────────────────────────
        if has_status:
            try:
                status_bytes = json.dumps(status_payload).encode()
                _publish_one(s, status_topic, status_bytes)
                log.debug('SIM-MQTT: status published')
            except Exception as e:
                log.warning(f'SIM-MQTT: status publish error: {e}')

        _send(s, 'AT+CMQTTDISC=0,120', 3.0)

    except Exception as e:
        log.error(f'SIM-MQTT: session error: {e}')
        try:
            _send(s, 'AT+CMQTTDISC=0,120', 2.0)
        except Exception:
            pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    if result["sent"]:
        log.info(f'SIM-MQTT: published {result["sent"]} GPS point(s) via SIM')
    return result
