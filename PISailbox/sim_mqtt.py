"""
SIM7600 AT-command MQTT uploader.

Publishes GPS points directly through the modem's built-in MQTT client,
bypassing PPP and HTTPS entirely.  Uses a public TCP MQTT broker (port 1883),
which this firmware supports even though it cannot do TLS.

Flow
----
1. gps_reader.pause()  — releases /dev/ttyAMA0
2. sim_mqtt.flush_via_mqtt(...)  — opens port, runs AT+CMQTT* commands, closes port
3. gps_reader.resume() — reclaims the port and restarts GPS engine

MQTT service state
------------------
The modem keeps AT+CMQTTSTART / AT+CMQTTACCQ alive until the modem restarts.
Errors 23 (service already started) and 19 (client already exists) are harmless
and are silently accepted.

Broker
------
Uses broker.hivemq.com:1883 (free, public, no auth required, plain TCP).
Override with PISAILBOX_MQTT_BROKER env var if using a private broker.
"""

import json
import os
import sqlite3
import time
import logging

log = logging.getLogger(__name__)

BROKER_URL = os.environ.get("PISAILBOX_MQTT_BROKER", "tcp://broker.hivemq.com:1883")
KEEPALIVE  = 60
TOPIC_ROOT = "pisailbox"


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


def _ensure_session(s, device_id):
    """Start MQTT service and acquire session 0.  Safe to call repeatedly."""
    resp = _send(s, 'AT+CMQTTSTART', 2.0)
    # error 23 = service already started — that's fine
    if 'ERROR' in resp and '+CMQTTSTART: 23' not in resp:
        raise RuntimeError(f'CMQTTSTART: {resp.strip()!r}')

    resp = _send(s, f'AT+CMQTTACCQ=0,"{device_id[:20]}"', 2.0)
    # error 19 = client already exists — that's fine
    if 'ERROR' in resp and '+CMQTTACCQ: 0,19' not in resp:
        raise RuntimeError(f'CMQTTACCQ: {resp.strip()!r}')


def _connect(s):
    _send(s, 'AT+CMQTTDISC=0,120', 3.0)   # error 11 = already disconnected, ignored
    resp = _send(s, f'AT+CMQTTCONNECT=0,"{BROKER_URL}",{KEEPALIVE},1', 10.0)
    if '+CMQTTCONNECT: 0,0' not in resp:
        raise RuntimeError(f'MQTT connect: {resp.strip()!r}')


def _publish_one(s, topic_bytes, payload_bytes):
    _write_data(s, f'AT+CMQTTTOPIC=0,{len(topic_bytes)}', topic_bytes)
    _write_data(s, f'AT+CMQTTPAYLOAD=0,{len(payload_bytes)}', payload_bytes)
    resp = _send(s, 'AT+CMQTTPUB=0,1,60', 10.0)
    if '+CMQTTPUB: 0,0' not in resp:
        raise RuntimeError(f'CMQTTPUB: {resp.strip()!r}')


def flush_via_mqtt(serial_port, baud_rate, device_id, track_id, db_path):
    """
    Read GPS points from the local SQLite queue and publish them via MQTT.
    Returns the number of points successfully published.
    """
    if not track_id:
        log.warning('SIM-MQTT: no active track — skipping')
        return 0

    try:
        with sqlite3.connect(db_path) as db:
            rows = db.execute(
                'SELECT id, payload FROM gps_queue WHERE attempts < 10 ORDER BY id LIMIT 5'
            ).fetchall()
    except Exception as e:
        log.warning(f'SIM-MQTT: cannot read queue: {e}')
        return 0

    if not rows:
        log.info('SIM-MQTT: queue is empty')
        return 0

    try:
        import serial as _serial
        s = _serial.Serial(serial_port, baud_rate, timeout=3, rtscts=False, dsrdtr=False)
        time.sleep(0.5)
        s.reset_input_buffer()
        _send(s, 'ATE0', 0.5)
    except Exception as e:
        log.warning(f'SIM-MQTT: cannot open serial port: {e}')
        return 0

    topic = f'{TOPIC_ROOT}/{device_id}/gps'.encode()
    sent  = 0

    try:
        _ensure_session(s, device_id)
        _connect(s)
        log.info(f'SIM-MQTT: connected — publishing to {topic.decode()}')

        for row_id, payload_str in rows:
            try:
                payload = json.loads(payload_str)
                payload['track_id'] = track_id
                payload_bytes = json.dumps(payload).encode()
                _publish_one(s, topic, payload_bytes)
                with sqlite3.connect(db_path) as db:
                    db.execute('DELETE FROM gps_queue WHERE id=?', (row_id,))
                sent += 1
                log.debug(f'SIM-MQTT: point {row_id} published')
            except Exception as e:
                log.warning(f'SIM-MQTT: point {row_id} error: {e}')
                with sqlite3.connect(db_path) as db:
                    db.execute('UPDATE gps_queue SET attempts=attempts+1 WHERE id=?', (row_id,))
                break   # stop this cycle on any error; retry next cycle

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

    if sent:
        log.info(f'SIM-MQTT: published {sent} point(s) via SIM')
    return sent
