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
            if not video_active.is_set():
                dur = device_config.get("video_duration_seconds", 60)
                t = threading.Thread(
                    target=_do_record_video, args=(dur,), daemon=True, name="cmd-video"
                )
                t.start()
            else:
                log.info("Video already recording")

        elif cmd == 'stop_video':
            # Signal video thread to stop (camera.py checks this event)
            video_active.clear()
            log.info("Video stop requested")

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

# ── GPS tracking thread ───────────────────────────────────────────────────────

def gps_thread_fn():
    log.info("GPS thread started")

    gps_reader.start()           # blocks until serial port opens successfully

    # Serial is now open — safe to use AT commands
    apn = device_config.get("sim_apn", "")
    if apn:
        log.info("Applying APN after serial open")
        sim_manager.apply_apn(apn,
                              user=device_config.get("sim_apn_user", ""),
                              password=device_config.get("sim_apn_pass", ""))

    current_track_id = None

    while not shutdown_event.is_set():
        poll_s = device_config.get("gps_poll_seconds", cfg.DEFAULT_CONFIG["gps_poll_seconds"])

        if tracking_active.is_set():
            # Ensure we have an open track on the server
            if not current_track_id:
                import zoneinfo
                est = zoneinfo.ZoneInfo("America/New_York")
                track_name = f"{cfg.DEVICE_ID} — {datetime.datetime.now(est).strftime('%Y-%m-%d %H:%M')} ET"
                current_track_id = uploader_inst.start_track(name=track_name)
                if current_track_id:
                    log.info(f"Track opened: id={current_track_id}")
                else:
                    log.warning("Could not open track, will retry")
                    shutdown_event.wait(5)
                    continue

            # Read and upload GPS point
            fix = gps_reader.get_fix()
            if fix and fix.is_valid():
                log.debug(f"GPS: {fix}")
                uploader_inst.upload_gps_point(fix)
            else:
                log.debug("Waiting for GPS fix…")

            uploader_inst.flush_gps_queue()

        else:
            # Tracking inactive — if we had an open track, close it
            if current_track_id:
                uploader_inst.stop_track()
                current_track_id = None
                log.info("Track closed")

        shutdown_event.wait(poll_s)

    # Clean shutdown
    if current_track_id:
        uploader_inst.stop_track()
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

        # Scheduled photo session
        if now >= next_photo_session:
            interval_s = device_config.get("photo_interval_seconds", 30)
            duration_m = device_config.get("photo_session_minutes", 60)
            next_photo_session = now + duration_m * 60

            def _run_session():
                camera_handler.run_photo_session(
                    interval_s, duration_m,
                    lambda: gps_reader.current_fix if gps_reader else None
                )
            threading.Thread(target=_run_session, daemon=True, name="photo-session").start()

        # Scheduled video recording (only if not already recording)
        video_sched = device_config.get("video_enabled", False)
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

def _on_config_change(new_cfg):
    # Apply APN only if the serial port is already open
    new_apn = new_cfg.get("sim_apn", "")
    if new_apn and sim_manager and gps_reader and gps_reader.is_ready:
        sim_manager.apply_apn(new_apn,
                              user=new_cfg.get("sim_apn_user", ""),
                              password=new_cfg.get("sim_apn_pass", ""))
    # Process any commands embedded in the config response
    commands = new_cfg.pop("__commands", []) or []
    if commands:
        handle_commands(commands)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global gps_reader, camera_handler, uploader_inst, device_config, sim_manager

    log.info(f"PiSailBox starting — device={cfg.DEVICE_ID}  server={cfg.SERVER_URL}")

    os.makedirs(cfg.DATA_DIR,   exist_ok=True)
    os.makedirs(cfg.PHOTOS_DIR, exist_ok=True)
    os.makedirs(cfg.VIDEOS_DIR, exist_ok=True)

    uploader_inst = Uploader(cfg.SERVER_URL, cfg.DEVICE_ID, cfg.QUEUE_DB)

    # Register and get initial config — retry until network is up
    log.info("Waiting for network…")
    initial_config = {}
    while not initial_config and not shutdown_event.is_set():
        initial_config = uploader_inst.register()
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
