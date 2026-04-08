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
  - Runs camera sessions on schedule (if camera_enabled + auto camera settings)
  - Reports SIM status periodically
"""

import os
import sys
import signal
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
import ppp as ppp_mgr

# ── Globals ───────────────────────────────────────────────────────────────────
shutdown_event    = threading.Event()
tracking_active   = threading.Event()   # set = tracking on, clear = tracking off
video_active      = threading.Event()   # set = video recording in progress

gps_reader:     GPSReader     = None
camera_handler: CameraHandler = None
uploader_inst:  Uploader      = None
device_config:  DeviceConfig  = None
sim_manager:    SIMManager    = None

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
        # Device-local time when this payload was assembled (for clock-skew debugging)
        "reported_at":      datetime.datetime.utcnow().isoformat() + "Z",
    }


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


def gps_thread_fn():
    log.info("GPS thread started")

    gps_reader.start()           # blocks until serial port opens successfully

    # Serial is now open — apply APN once and record it so _on_config_change
    # doesn't re-apply it on every subsequent poll
    global _last_applied_apn
    apn  = device_config.get("sim_apn", "")
    user = device_config.get("sim_apn_user", "")
    pw   = device_config.get("sim_apn_pass", "")
    if apn:
        log.info("Applying APN after serial open")
        sim_manager.apply_apn(apn, user=user, password=pw)
        _last_applied_apn = f"{apn}|{user}|{pw}"

    current_track_id = None
    next_diag_report  = time.time()
    next_gps_upload   = time.time()   # next batch upload to server

    while not shutdown_event.is_set():
        poll_s = max(3, int(device_config.get("gps_poll_seconds", cfg.DEFAULT_CONFIG["gps_poll_seconds"]) or 10))
        # Batch upload (SIM MQTT + config subscribe) uses website check-in interval
        _ci = device_config.get("config_poll_interval_seconds")
        _gu = device_config.get("gps_upload_interval_seconds")
        try:
            upload_s = max(5, int(_ci if _ci is not None else _gu if _gu is not None
                else cfg.DEFAULT_CONFIG.get("gps_upload_interval_seconds", 30)))
        except (TypeError, ValueError):
            upload_s = 30

        if tracking_active.is_set():
            # Ensure we have an open track on the server
            if not current_track_id:
                import zoneinfo
                est = zoneinfo.ZoneInfo("America/New_York")
                now_est = datetime.datetime.now(est)
                track_name = f"{cfg.DEVICE_ID} — {now_est.strftime('%Y-%m-%d %H:%M')} ET"

                # Prefer server-assigned track_id (set by command handler, arrives via
                # HTTP config poll or MQTT config topic)
                server_track_id = device_config.get("active_track_id") or uploader_inst._track_id
                if server_track_id:
                    current_track_id = server_track_id
                    uploader_inst._track_id = server_track_id
                    uploader_inst._save_track_id(server_track_id)
                    log.info(f"▶ Track RESUMED  id={current_track_id}  (server-assigned)")
                else:
                    # Fall back to creating a track via HTTP (needs WiFi)
                    current_track_id = uploader_inst.start_track(name=track_name)
                    if current_track_id:
                        log.info(f"▶ Track STARTED  id={current_track_id}  name='{track_name}'  at {now_est.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                    else:
                        # No WiFi and no server assignment — try persisted id
                        fallback = uploader_inst.load_persisted_track_id()
                        if fallback:
                            current_track_id = fallback
                            log.warning(f"No network — resuming persisted track id={current_track_id} (SIM MQTT will upload when fix arrives)")
                        else:
                            log.warning("No network and no persisted track — will retry in 15s")
                            shutdown_event.wait(15)
                            continue

            # Read GPS and store locally every poll_s seconds
            fix = gps_reader.get_fix()
            if fix and fix.is_valid():
                log.info(f"GPS fix: lat={fix.lat:.5f} lng={fix.lng:.5f} spd={fix.speed}")
                uploader_inst.queue_gps_point(fix)   # store locally
            else:
                log.info("GPS: no fix yet — waiting for satellites")

            # Upload queued points every upload_s seconds — SIM MQTT only.
            # WiFi is NOT used for GPS; all points go via the modem's AT+CMQTT stack
            # so it's always clear whether the SIM path is working.
            now = time.time()
            if now >= next_gps_upload:
                next_gps_upload = now + upload_s
                depth = uploader_inst.gps_queue_depth()
                log.info(f"GPS: upload tick — {depth} point(s) in queue")

                global _last_upload_via, _last_upload_at

                # Build a compact status payload to publish alongside GPS data
                _status = _build_gps_diag(current_track_id)

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
                        log.info(f"GPS: published {sent} point(s) via SIM MQTT")
                        _last_upload_via = "SIM"
                        _last_upload_at  = datetime.datetime.utcnow().isoformat() + "Z"
                    elif depth > 0:
                        log.warning("GPS: SIM MQTT — 0 sent (check SIM connected and track active)")

                    # Apply any config / commands the server pushed via retained MQTT
                    _apply_mqtt_config(mqtt_result.get("config"), current_track_id)

                except Exception as _sim_e:
                    log.error(f"GPS: SIM MQTT error: {_sim_e}")
                finally:
                    gps_reader.resume()

        else:
            # Tracking inactive — if we had an open track, close it
            if current_track_id:
                import zoneinfo
                est = zoneinfo.ZoneInfo("America/New_York")
                now_est = datetime.datetime.now(est)
                uploader_inst.stop_track()
                log.info(f"⏹ Track STOPPED  id={current_track_id}  at {now_est.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                current_track_id = None

        # Report GPS diagnostics periodically (every ~60 s)
        now = time.time()
        if now >= next_diag_report:
            next_diag_report = now + 60
            try:
                uploader_inst.report_gps_status(_build_gps_diag(current_track_id))
            except Exception as _e:
                log.debug(f"GPS diag upload error: {_e}")

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
    log.info("SIM status thread started")
    while not shutdown_event.is_set():
        try:
            status = sim_manager.get_status()
            log.info(
                f"SIM: op={status.get('operator')} type={status.get('network_type')} "
                f"sig={status.get('signal_percent')}% reg={status.get('registration')}"
            )
            uploader_inst.report_sim_status(status)
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
    global gps_reader, camera_handler, uploader_inst, device_config, sim_manager

    service_started_at = datetime.datetime.utcnow().isoformat() + "Z"
    log.info(f"PiSailBox starting — device={cfg.DEVICE_ID}  server={cfg.SERVER_URL}  started={service_started_at}")

    os.makedirs(cfg.DATA_DIR,   exist_ok=True)
    os.makedirs(cfg.PHOTOS_DIR, exist_ok=True)
    os.makedirs(cfg.VIDEOS_DIR, exist_ok=True)

    uploader_inst = Uploader(cfg.SERVER_URL, cfg.DEVICE_ID, cfg.QUEUE_DB,
                             track_id_file=cfg.TRACK_ID_FILE)

    # Register and get initial config — retry until network is up
    log.info("Waiting for network…")
    initial_config = {}
    while not initial_config and not shutdown_event.is_set():
        initial_config = uploader_inst.register(started_at=service_started_at)
        if not initial_config:
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
