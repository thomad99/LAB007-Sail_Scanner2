#!/usr/bin/env python3
"""
PiSailBox — main entry point.

Starts on boot (via systemd), registers with the server, then:
  - Starts GPS tracking only if auto_track=true OR a start_track command arrives
  - Responds to remote commands from the PiControl portal:
      start_track    — begin uploading GPS
      stop_track     — stop uploading GPS
      capture_photo  — take one photo immediately
      start_video    — start a video recording
      stop_video     — stop the current video recording
      reboot         — full system reboot (requires NOPASSWD sudo for /sbin/reboot; see install.sh)
  - Runs camera sessions on schedule (if camera_enabled + auto camera settings)
  - Reports SIM status periodically
"""

import os
import sys
import json
import signal
import subprocess
import threading
import time
import logging
import datetime

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.expanduser("~/pisailbox_data/pisailbox.log"),
            encoding="utf-8"
        )
    ]
)
log = logging.getLogger("main")

import config as cfg
from gps      import GPSReader
from camera   import CameraHandler
from uploader import Uploader
from device   import DeviceConfig
from sim      import SIMManager

# Last-known server config (SIM/MQTT path) — used if HTTPS register fails (no WiFi)
CONFIG_CACHE_FILE = os.path.join(cfg.DATA_DIR, "cached_server_config.json")


def _load_cached_config():
    try:
        with open(CONFIG_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _save_cached_config(config_dict):
    if not config_dict:
        return
    try:
        os.makedirs(cfg.DATA_DIR, exist_ok=True)
        snap = {k: v for k, v in config_dict.items() if k != "__commands"}
        with open(CONFIG_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(snap, f)
    except OSError as e:
        log.warning(f"Could not save config cache: {e}")


# ── Globals ───────────────────────────────────────────────────────────────────
shutdown_event    = threading.Event()
tracking_active   = threading.Event()   # set = tracking on, clear = tracking off
video_active      = threading.Event()   # set = video recording in progress

gps_reader:     GPSReader     = None
camera_handler: CameraHandler = None
uploader_inst:  Uploader      = None
device_config:  DeviceConfig  = None
sim_manager:    SIMManager    = None

# GNSS soft-recover (AT+CGPS cycle) — at most two tries per tracking session
_gnss_recoveries = 0

# Wall-clock when this Python process started (sent on every status upload for server UI)
SERVICE_PROCESS_STARTED_AT = None

# ── Signal handling ───────────────────────────────────────────────────────────

def _handle_signal(sig, frame):
    log.info(f"Signal {sig} — shutting down")
    shutdown_event.set()
    tracking_active.clear()
    video_active.clear()

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)

# ── Command processor ─────────────────────────────────────────────────────────

def handle_commands(commands):
    """Process a list of command strings received from the server."""
    for cmd in commands:
        log.info(f"Command received: {cmd}")
        if cmd == 'start_track':
            if not tracking_active.is_set():
                tracking_active.set()
                log.info("Tracking STARTED by remote command")
            else:
                log.info("Tracking already active")

        elif cmd == 'stop_track':
            if tracking_active.is_set():
                tracking_active.clear()
                log.info("Tracking STOPPED by remote command")
            else:
                log.info("Tracking already inactive")

        elif cmd == 'capture_photo':
            t = threading.Thread(
                target=_do_capture_photo, daemon=True, name="cmd-photo"
            )
            t.start()

        elif cmd == 'start_video':
            if not device_config.get("camera_enabled", False):
                log.warning("start_video ignored — camera master switch is OFF")
            elif video_active.is_set():
                log.info("Video already recording")
            else:
                dur = device_config.get("video_duration_seconds", 60)
                t = threading.Thread(
                    target=_do_record_video, args=(dur,), daemon=True, name="cmd-video"
                )
                t.start()

        elif cmd == 'stop_video':
            if not video_active.is_set():
                log.info("stop_video ignored — not currently recording")
            else:
                video_active.clear()
                log.info("Video stop requested")

        elif cmd == 'restart':
            log.info("Restart command received — exiting cleanly (systemd will restart)")
            shutdown_event.set()
            tracking_active.clear()
            video_active.clear()

        elif cmd == 'reboot':
            log.warning("Reboot command received — full system reboot in ~3s (see pisailbox.log on next boot)")

            def _delayed_reboot():
                time.sleep(3)
                for path in ("/sbin/reboot", "/usr/sbin/reboot"):
                    if os.path.isfile(path):
                        try:
                            subprocess.run(["sudo", path], check=False, timeout=60)
                            return
                        except Exception as ex:
                            log.error(f"reboot via {path} failed: {ex}")
                log.error("reboot: no /sbin/reboot — install sudoers (install.sh) or run manually")

            threading.Thread(target=_delayed_reboot, daemon=True, name="system-reboot").start()

        elif cmd == 'test_sim':
            t = threading.Thread(
                target=_do_test_sim, daemon=True, name="cmd-test-sim"
            )
            t.start()

def _do_capture_photo():
    fix = gps_reader.current_fix if gps_reader else None
    path = camera_handler.capture_photo(gps_fix=fix)
    if path:
        uploader_inst.upload_photos([(path, fix)])

def _do_record_video(duration_s):
    video_active.set()
    try:
        camera_handler.record_video(duration_s)
    finally:
        video_active.clear()

def _do_test_sim():
    """Force a SIM MQTT upload regardless of WiFi. Reports result via gps_status."""
    global _last_upload_via, _last_upload_at
    log.info("SIM TEST: starting forced SIM MQTT upload test")
    try:
        fix = gps_reader.current_fix if gps_reader else None
        if fix:
            uploader_inst.queue_gps_point(fix)

        depth = uploader_inst.gps_queue_depth()
        log.info(f"SIM TEST: {depth} point(s) in queue — pausing GPS for MQTT upload")

        gps_reader.pause()
        try:
            import sim_mqtt
            sent = sim_mqtt.flush_via_mqtt(
                serial_port = cfg.GPS_SERIAL_PORT,
                baud_rate   = cfg.GPS_BAUD_RATE,
                device_id   = cfg.DEVICE_ID,
                track_id    = uploader_inst._track_id,
                db_path     = uploader_inst.db_path,
            )
            if sent > 0:
                log.info(f"SIM TEST: SUCCESS — published {sent} point(s) via SIM MQTT")
                _last_upload_via = "SIM"
                _last_upload_at  = datetime.datetime.utcnow().isoformat() + "Z"
            else:
                log.warning("SIM TEST: MQTT upload returned 0 — check track is active")
        except Exception as e:
            log.error(f"SIM TEST: MQTT error: {e}")
        finally:
            gps_reader.resume()

        try:
            uploader_inst.report_gps_status(_build_gps_diag(None))
        except Exception:
            pass
    except Exception as e:
        log.error(f"SIM TEST error: {e}")

# ── GPS tracking thread ───────────────────────────────────────────────────────

_last_upload_via     = None   # "WiFi" | "SIM" | None
_last_upload_at      = None   # ISO timestamp of last successful upload

def _build_gps_diag(current_track_id):
    """Build GPS diagnostic dict to upload to the server."""
    fix = gps_reader.current_fix if gps_reader else None
    return {
        "pisailbox_process_started_at": SERVICE_PROCESS_STARTED_AT,
        "serial_open":      gps_reader.is_ready        if gps_reader else False,
        "gps_engine_on":    gps_reader.gps_engine_on   if gps_reader else False,
        "fix_valid":        bool(fix and fix.is_valid()),
        "lat":              fix.lat   if fix else None,
        "lng":              fix.lng   if fix else None,
        "altitude":         fix.altitude if fix else None,
        "speed_ms":         fix.speed    if fix else None,
        "fix_count":        gps_reader.fix_count      if gps_reader else 0,
        "no_fix_count":     gps_reader.no_fix_count   if gps_reader else 0,
        "last_error":       gps_reader.last_error      if gps_reader else None,
        "recent_errors":    list(gps_reader._recent_errors) if gps_reader else [],
        "tracking_active":  tracking_active.is_set(),
        "track_id":         current_track_id,
        "last_fix_at":      gps_reader.last_fix_at_iso if gps_reader and fix and fix.is_valid() else None,
        "last_upload_via":  _last_upload_via,
        "last_upload_at":   _last_upload_at,
        "gps_queue_pending": uploader_inst.gps_queue_depth() if uploader_inst else 0,
        # Device-local time when this payload was assembled (for clock-skew debugging)
        "reported_at":      datetime.datetime.utcnow().isoformat() + "Z",
    }


def _build_mqtt_status_payload(current_track_id):
    """
    Full status for pisailbox/{id}/status over SIM MQTT (no WiFi).
    Includes SIM/modem snapshot so the website stays updated off-WiFi.
    """
    payload = _build_gps_diag(current_track_id)
    try:
        if sim_manager:
            sm = sim_manager.get_status()
            if sm:
                payload["sim_modem"] = sm
    except Exception as e:
        payload["sim_modem_error"] = str(e)
    return payload


_last_processed_cmd_id = None   # dedup one-shot MQTT commands


def _apply_mqtt_config(mqtt_cfg, current_track_id):
    """
    Process config + commands received from the server via MQTT retained message.
    Updates device_config, handles active_track_id, and fires commands.
    Called from the GPS thread after each MQTT cycle.
    """
    global _last_processed_cmd_id
    if not mqtt_cfg:
        return

    # Apply config settings (fires _on_config_change callback, handles auto_track, APN, etc.)
    device_config.update(mqtt_cfg)

    # Apply server-assigned active_track_id if it has changed
    server_track_id = mqtt_cfg.get("active_track_id")
    if server_track_id and server_track_id != uploader_inst._track_id:
        log.info(f"MQTT config: server assigned track_id={server_track_id} — adopting")
        uploader_inst._track_id = server_track_id
        uploader_inst._save_track_id(server_track_id)
    elif not server_track_id and uploader_inst._track_id:
        # Server cleared the track (stop_track was pressed)
        log.info("MQTT config: server cleared active_track_id — stopping track")
        uploader_inst._track_id = None
        uploader_inst._clear_track_id_file()

    # Process one-shot commands embedded in __commands
    commands = mqtt_cfg.get("__commands", [])
    if isinstance(commands, list) and commands:
        # Each command may be a plain string or {"cmd": "...", "cmd_id": "..."}
        for item in commands:
            if isinstance(item, dict):
                cmd    = item.get("cmd", "")
                cmd_id = item.get("cmd_id")
                if cmd_id and cmd_id == _last_processed_cmd_id:
                    continue   # already processed this one
            else:
                cmd    = item
                cmd_id = None

            # skip track commands — handled via active_track_id above
            if cmd in ('start_track', 'stop_track'):
                continue

            log.info(f"MQTT command: {cmd}")
            handle_commands([cmd])
            if cmd_id:
                _last_processed_cmd_id = cmd_id

    try:
        if device_config:
            _save_cached_config(device_config.all())
    except Exception:
        pass


def gps_thread_fn():
    global _last_upload_via, _last_upload_at, _gnss_recoveries
    log.info("GPS thread started")

    if cfg.MODEM_SETTLE_SECONDS > 0:
        log.info(f"Cold-boot modem settle {cfg.MODEM_SETTLE_SECONDS}s before opening GPS UART")
        time.sleep(cfg.MODEM_SETTLE_SECONDS)

    gps_reader.start()           # blocks until serial port opens successfully

    # Serial is now open — apply APN once after a delay so PDP setup does not run
    # immediately on top of AT+CGPS=1 (common cold-start GNSS flake source).
    global _last_applied_apn
    apn  = device_config.get("sim_apn", "")
    user = device_config.get("sim_apn_user", "")
    pw   = device_config.get("sim_apn_pass", "")
    if apn:
        if cfg.APN_APPLY_DELAY_SECONDS > 0:
            log.info(
                f"Deferring APN configuration {cfg.APN_APPLY_DELAY_SECONDS}s "
                "(lets GNSS engine start before PDP context changes)"
            )
            time.sleep(cfg.APN_APPLY_DELAY_SECONDS)
        log.info("Applying APN after GPS UART init")
        sim_manager.apply_apn(apn, user=user, password=pw)
        _last_applied_apn = f"{apn}|{user}|{pw}"

    current_track_id = None
    # SIM/MQTT: config, GPS points, and full status — same cadence, WiFi not required
    next_mqtt_cycle = 0.0

    while not shutdown_event.is_set():
        poll_s    = device_config.get("gps_poll_seconds",            cfg.DEFAULT_CONFIG["gps_poll_seconds"])
        upload_s  = device_config.get("gps_upload_interval_seconds", cfg.DEFAULT_CONFIG.get("gps_upload_interval_seconds", 60))

        if tracking_active.is_set():
            # Ensure we have an open track on the server
            if not current_track_id:
                import zoneinfo
                est = zoneinfo.ZoneInfo("America/New_York")
                now_est = datetime.datetime.now(est)
                track_name = f"{cfg.DEVICE_ID} — {now_est.strftime('%Y-%m-%d %H:%M')} ET"

                # Prefer server-assigned track_id (MQTT retained config or HTTP)
                server_track_id = device_config.get("active_track_id") or uploader_inst._track_id
                if server_track_id:
                    current_track_id = server_track_id
                    uploader_inst._track_id = server_track_id
                    uploader_inst._save_track_id(server_track_id)
                    log.info(f"▶ Track RESUMED  id={current_track_id}  (server-assigned)")
                    _gnss_recoveries = 0
                else:
                    # Creating a track via HTTPS (needs a routed internet path, e.g. WiFi)
                    current_track_id = uploader_inst.start_track(name=track_name)
                    if current_track_id:
                        log.info(f"▶ Track STARTED  id={current_track_id}  name='{track_name}'  at {now_est.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                        _gnss_recoveries = 0
                    else:
                        fallback = uploader_inst.load_persisted_track_id()
                        if fallback:
                            current_track_id = fallback
                            log.warning(f"No HTTPS — resuming persisted track id={current_track_id} (SIM MQTT)")
                            _gnss_recoveries = 0
                        else:
                            log.warning("No HTTPS and no persisted track — retry in 15s")
                            shutdown_event.wait(15)
                            continue

            fix = gps_reader.get_fix()
            if fix and fix.is_valid():
                _gnss_recoveries = 0
                log.info(f"GPS fix: lat={fix.lat:.5f} lng={fix.lng:.5f} spd={fix.speed}")
                uploader_inst.queue_gps_point(fix)
            else:
                log.info("GPS: no fix yet — waiting for satellites")
                n = gps_reader.no_fix_count
                if n >= 45 and _gnss_recoveries == 0:
                    _gnss_recoveries = 1
                    gps_reader.recover_gnss()
                elif n >= 95 and _gnss_recoveries == 1:
                    _gnss_recoveries = 2
                    gps_reader.recover_gnss()

        else:
            if current_track_id:
                import zoneinfo
                est = zoneinfo.ZoneInfo("America/New_York")
                now_est = datetime.datetime.now(est)
                uploader_inst.stop_track()
                log.info(f"⏹ Track STOPPED  id={current_track_id}  at {now_est.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                current_track_id = None
                _gnss_recoveries = 0

        now = time.time()
        if now >= next_mqtt_cycle:
            next_mqtt_cycle = now + upload_s
            depth = uploader_inst.gps_queue_depth()
            log.info(f"SIM-MQTT cycle — queue={depth} pt(s), tracking={tracking_active.is_set()}")

            _status = _build_mqtt_status_payload(current_track_id)

            gps_reader.pause()
            try:
                import sim_mqtt
                mqtt_result = sim_mqtt.flush_via_mqtt(
                    serial_port    = cfg.GPS_SERIAL_PORT,
                    baud_rate      = cfg.GPS_BAUD_RATE,
                    device_id      = cfg.DEVICE_ID,
                    track_id       = uploader_inst._track_id,
                    db_path        = uploader_inst.db_path,
                    status_payload = _status,
                )
                sent = mqtt_result["sent"]
                if sent > 0:
                    log.info(f"SIM-MQTT: published {sent} GPS point(s)")
                    _last_upload_via = "SIM"
                    _last_upload_at  = datetime.datetime.utcnow().isoformat() + "Z"
                elif depth > 0 and tracking_active.is_set():
                    log.warning("SIM-MQTT: 0 points sent (check track id / PDP context)")

                _apply_mqtt_config(mqtt_result.get("config"), current_track_id)

            except Exception as _sim_e:
                log.error(f"SIM-MQTT error: {_sim_e}")
            finally:
                gps_reader.resume()

        shutdown_event.wait(poll_s)

    # Clean shutdown
    if current_track_id:
        import zoneinfo
        est = zoneinfo.ZoneInfo("America/New_York")
        now_est = datetime.datetime.now(est)
        uploader_inst.stop_track()
        log.info(f"⏹ Track STOPPED (shutdown)  id={current_track_id}  at {now_est.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    gps_reader.stop()
    log.info("GPS thread stopped")

# ── Camera thread ─────────────────────────────────────────────────────────────

def camera_thread_fn():
    log.info("Camera thread started")

    next_photo_session = time.time()
    next_video         = time.time()
    next_upload        = time.time()

    while not shutdown_event.is_set():
        now = time.time()
        cam_enabled = device_config.get("camera_enabled", False)

        if not cam_enabled:
            shutdown_event.wait(10)
            continue

        # Scheduled photo session (only when auto-photo is enabled)
        if device_config.get("camera_auto_photo", False) and now >= next_photo_session:
            interval_s = device_config.get("photo_interval_seconds", 30)
            duration_m = device_config.get("photo_session_minutes", 60)
            next_photo_session = now + duration_m * 60

            def _run_session():
                camera_handler.run_photo_session(
                    interval_s, duration_m,
                    lambda: gps_reader.current_fix if gps_reader else None,
                    stop_event=shutdown_event,
                    should_continue=lambda: (
                        device_config.get("camera_enabled", False) and
                        device_config.get("camera_auto_photo", False)
                    )
                )
            threading.Thread(target=_run_session, daemon=True, name="photo-session").start()

        # Scheduled video recording — needs camera enabled AND auto-record on
        video_sched = device_config.get("camera_enabled", False) and \
                      device_config.get("video_auto_record", False)
        if video_sched and not video_active.is_set() and now >= next_video:
            v_interval = device_config.get("video_interval_minutes", 10) * 60
            v_duration = device_config.get("video_duration_seconds", 60)
            next_video = now + v_interval
            threading.Thread(
                target=_do_record_video, args=(v_duration,),
                daemon=True, name="sched-video"
            ).start()

        # Upload pending photos
        upload_interval = device_config.get("photo_upload_interval_minutes", 5) * 60
        if now >= next_upload:
            next_upload = now + upload_interval
            batch = list(camera_handler.upload_queue)
            camera_handler.upload_queue.clear()
            if batch:
                uploader_inst.upload_photos(batch)
            uploader_inst.flush_photo_queue()

        shutdown_event.wait(10)

    camera_handler.close()
    log.info("Camera thread stopped")

# ── SIM status thread ─────────────────────────────────────────────────────────

def sim_thread_fn():
    """Log modem stats; website SIM card is updated via SIM-MQTT status payload (no HTTPS)."""
    log.info("SIM status thread started")
    while not shutdown_event.is_set():
        try:
            status = sim_manager.get_status()
            log.info(
                f"SIM: op={status.get('operator')} type={status.get('network_type')} "
                f"sig={status.get('signal_percent')}% reg={status.get('registration')}"
            )
        except Exception as e:
            log.warning(f"SIM status failed: {e}")
        interval = device_config.get("sim_status_interval_seconds", 60)
        shutdown_event.wait(interval)
    log.info("SIM status thread stopped")

# ── Config change handler ─────────────────────────────────────────────────────

_last_applied_apn = None   # track last APN so we only re-apply when it changes

def _on_config_change(new_cfg):
    global _last_applied_apn
    # Apply APN only when it has actually changed (not on every 30s config poll)
    new_apn  = new_cfg.get("sim_apn", "")
    new_user = new_cfg.get("sim_apn_user", "")
    new_pass = new_cfg.get("sim_apn_pass", "")
    apn_key  = f"{new_apn}|{new_user}|{new_pass}"
    if new_apn and sim_manager and gps_reader and gps_reader.is_ready:
        if apn_key != _last_applied_apn:
            log.info(f"APN changed — applying: {new_apn}")
            sim_manager.apply_apn(new_apn, user=new_user, password=new_pass)
            _last_applied_apn = apn_key
        else:
            log.debug("APN unchanged — skipping re-apply")

    # React to auto_track being toggled live in PiControl (not just at startup)
    if new_cfg.get("auto_track", False) and not tracking_active.is_set():
        log.info("auto_track became true — starting GPS tracking")
        tracking_active.set()
    elif not new_cfg.get("auto_track", False) and tracking_active.is_set():
        # auto_track turned off AND no explicit start_track was issued — stop tracking
        # (only if it was auto-started; manual start_track commands take precedence via
        # tracking_active being set before this callback fires)
        pass  # do not auto-stop; let the user explicitly press Stop Tracking

    # Process any commands embedded in the config response
    commands = new_cfg.pop("__commands", []) or []
    if commands:
        handle_commands(commands)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global gps_reader, camera_handler, uploader_inst, device_config, sim_manager, SERVICE_PROCESS_STARTED_AT

    service_started_at = datetime.datetime.utcnow().isoformat() + "Z"
    SERVICE_PROCESS_STARTED_AT = service_started_at
    log.info(f"PiSailBox starting — device={cfg.DEVICE_ID}  server={cfg.SERVER_URL}  started={service_started_at}")

    os.makedirs(cfg.DATA_DIR,   exist_ok=True)
    os.makedirs(cfg.PHOTOS_DIR, exist_ok=True)
    os.makedirs(cfg.VIDEOS_DIR, exist_ok=True)

    uploader_inst = Uploader(cfg.SERVER_URL, cfg.DEVICE_ID, cfg.QUEUE_DB,
                             track_id_file=cfg.TRACK_ID_FILE)

    # HTTPS register and/or cached config — SIM-only operation after first successful sync
    log.info("Waiting for server config (HTTPS or cached file)…")
    initial_config = None
    while initial_config is None and not shutdown_event.is_set():
        reg = uploader_inst.register(started_at=service_started_at)
        if reg is not None:
            initial_config = reg
            _save_cached_config(reg)
            log.info("Registered with server via HTTPS")
            break
        cached = _load_cached_config()
        if cached:
            initial_config = cached
            log.warning("HTTPS register failed — using cached config (SIM MQTT will sync)")
            break
        log.warning("Registration failed — retrying in 15s")
        shutdown_event.wait(15)

    if shutdown_event.is_set():
        return

    # Strip out any commands bundled with initial config
    initial_commands = initial_config.pop("__commands", []) or []

    log.info(f"Initial config: {initial_config}")

    device_config = DeviceConfig(uploader_inst, initial_config)
    device_config.on_change(_on_config_change)
    device_config.start_polling()

    # Process any commands that arrived at registration time
    if initial_commands:
        handle_commands(initial_commands)

    # Set tracking state from auto_track config
    if device_config.get("auto_track", False):
        log.info("auto_track=true — starting GPS tracking automatically")
        tracking_active.set()

    # Hardware
    gps_reader     = GPSReader(cfg.GPS_SERIAL_PORT, cfg.GPS_BAUD_RATE)
    upload_queue   = []
    camera_handler = CameraHandler(cfg.PHOTOS_DIR, cfg.VIDEOS_DIR, upload_queue)
    sim_manager    = SIMManager(gps_reader)
    # APN is applied inside gps_thread_fn after the serial port opens

    # Start worker threads
    threads = [
        threading.Thread(target=gps_thread_fn,    daemon=True, name="gps"),
        threading.Thread(target=camera_thread_fn, daemon=True, name="camera"),
        threading.Thread(target=sim_thread_fn,    daemon=True, name="sim"),
    ]
    for t in threads:
        t.start()

    log.info("All services running")
    shutdown_event.wait()
    log.info("Shutdown complete")


if __name__ == "__main__":
    main()
