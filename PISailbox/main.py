#!/usr/bin/env python3
"""
PiSailBox — main entry point.

Starts on boot (via systemd), registers with the server,
then runs GPS tracking and camera capture concurrently.
Stops cleanly when the Pi is powered off (SIGTERM/SIGINT).
"""

import os
import sys
import signal
import threading
import time
import logging
import datetime

# ── Configure logging ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.expanduser("~/pisailbox_data/pisailbox.log"),
                            encoding="utf-8")
    ]
)
log = logging.getLogger("main")

# ── Local imports ─────────────────────────────────────────────────────────────
import config as cfg
from gps      import GPSReader
from camera   import CameraHandler
from uploader import Uploader
from device   import DeviceConfig
from sim      import SIMManager

# ── Globals ───────────────────────────────────────────────────────────────────
shutdown_event = threading.Event()
camera_handler: CameraHandler = None
gps_reader: GPSReader         = None
uploader_inst: Uploader       = None
device_config: DeviceConfig   = None
sim_manager: SIMManager       = None

# ── Signal handling ───────────────────────────────────────────────────────────

def _handle_signal(sig, frame):
    log.info(f"Signal {sig} received — shutting down…")
    shutdown_event.set()

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)

# ── GPS tracking thread ───────────────────────────────────────────────────────

def gps_thread_fn():
    """
    Opens GPS, starts a server-side track, then uploads one point
    every gps_poll_seconds until shutdown.
    """
    log.info("GPS thread started")

    gps_reader.start()           # blocks until serial opens successfully
    track_id = uploader_inst.start_track()

    if not track_id:
        # Retry loop — network may not be up yet
        log.warning("Could not create server track; retrying…")
        while not shutdown_event.is_set():
            time.sleep(10)
            track_id = uploader_inst.start_track()
            if track_id:
                break

    log.info(f"GPS: uploading to track {track_id}")

    while not shutdown_event.is_set():
        poll_s = device_config.get("gps_poll_seconds", cfg.DEFAULT_CONFIG["gps_poll_seconds"])
        fix    = gps_reader.get_fix()

        if fix and fix.is_valid():
            log.debug(f"GPS fix: {fix}")
            uploader_inst.upload_gps_point(fix)
        else:
            log.debug("Waiting for GPS fix…")

        # Also flush any queued points from previous network outages
        uploader_inst.flush_gps_queue()

        shutdown_event.wait(poll_s)

    uploader_inst.stop_track()
    gps_reader.stop()
    log.info("GPS thread stopped")

# ── Camera thread ─────────────────────────────────────────────────────────────

def camera_thread_fn():
    """
    Runs photo sessions and optional video recordings on schedule.
    Respects config changes via device_config polling.
    """
    log.info("Camera thread started")
    photo_queue = []

    # Inner flag so we can tell get_gps_fix which fix is current
    def get_current_fix():
        return gps_reader.current_fix if gps_reader else None

    next_photo_session = time.time()
    next_video         = time.time()
    next_upload        = time.time()

    while not shutdown_event.is_set():
        now = time.time()
        cam_enabled = device_config.get("camera_enabled", False)

        if not cam_enabled:
            shutdown_event.wait(10)
            continue

        # ── Photo session ─────────────────────────────────────────────────
        if now >= next_photo_session:
            interval_s  = device_config.get("photo_interval_seconds", 30)
            duration_m  = device_config.get("photo_session_minutes",  60)
            next_photo_session = now + duration_m * 60

            def _run_session():
                camera_handler.run_photo_session(
                    interval_s, duration_m, get_current_fix
                )
                # After session, flush upload queue
                batch = list(camera_handler.upload_queue)
                camera_handler.upload_queue.clear()
                if batch:
                    uploader_inst.upload_photos(batch)

            t = threading.Thread(target=_run_session, daemon=True, name="photo-session")
            t.start()

        # ── Video recording ───────────────────────────────────────────────
        video_enabled = device_config.get("video_enabled", False)
        if video_enabled and now >= next_video:
            v_interval_s  = device_config.get("video_interval_minutes", 10) * 60
            v_duration_s  = device_config.get("video_duration_seconds", 60)
            next_video    = now + v_interval_s

            def _run_video():
                camera_handler.record_video(v_duration_s)

            t = threading.Thread(target=_run_video, daemon=True, name="video-rec")
            t.start()

        # ── Upload pending photos ─────────────────────────────────────────
        upload_interval_m = device_config.get("photo_upload_interval_minutes", 5)
        if now >= next_upload:
            next_upload = now + upload_interval_m * 60
            batch = list(camera_handler.upload_queue)
            camera_handler.upload_queue.clear()
            if batch:
                uploader_inst.upload_photos(batch)
            uploader_inst.flush_photo_queue()

        shutdown_event.wait(10)

    camera_handler.close()
    log.info("Camera thread stopped")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global gps_reader, camera_handler, uploader_inst, device_config

    log.info(f"PiSailBox starting — device_id={cfg.DEVICE_ID}, server={cfg.SERVER_URL}")

    # Ensure data directories exist
    os.makedirs(cfg.DATA_DIR,   exist_ok=True)
    os.makedirs(cfg.PHOTOS_DIR, exist_ok=True)
    os.makedirs(cfg.VIDEOS_DIR, exist_ok=True)

    # Create uploader first (needed for registration)
    uploader_inst = Uploader(cfg.SERVER_URL, cfg.DEVICE_ID, cfg.QUEUE_DB)

    # Register and get initial config (retry until network is up)
    log.info("Waiting for network…")
    initial_config = {}
    while not initial_config and not shutdown_event.is_set():
        initial_config = uploader_inst.register()
        if not initial_config:
            log.warning("Registration failed, retrying in 15s…")
            shutdown_event.wait(15)

    if shutdown_event.is_set():
        return

    log.info(f"Initial config: {initial_config}")

    # Set up device config manager
    device_config = DeviceConfig(uploader_inst, initial_config)
    device_config.start_polling()

    # Set up GPS reader
    gps_reader = GPSReader(cfg.GPS_SERIAL_PORT, cfg.GPS_BAUD_RATE)

    # Set up camera handler
    upload_queue = []
    camera_handler = CameraHandler(cfg.PHOTOS_DIR, cfg.VIDEOS_DIR, upload_queue)

    # SIM manager (shares GPS serial port — GPS must be started first)
    sim_manager = SIMManager(gps_reader)

    # Apply APN from server config if one is set
    apn = device_config.get("sim_apn", "")
    if apn:
        sim_manager.apply_apn(apn,
                              user=device_config.get("sim_apn_user", ""),
                              password=device_config.get("sim_apn_pass", ""))

    # Re-apply APN whenever config changes
    def _on_config_change(new_cfg):
        new_apn = new_cfg.get("sim_apn", "")
        if new_apn:
            sim_manager.apply_apn(new_apn,
                                  user=new_cfg.get("sim_apn_user", ""),
                                  password=new_cfg.get("sim_apn_pass", ""))
    device_config.on_change(_on_config_change)

    # SIM status reporter
    def sim_report_thread_fn():
        log.info("SIM status reporter started")
        while not shutdown_event.is_set():
            try:
                status = sim_manager.get_status()
                log.info(
                    f"SIM: op={status.get('operator')} type={status.get('network_type')} "
                    f"sig={status.get('signal_percent')}% reg={status.get('registration')}"
                )
                uploader_inst.report_sim_status(status)
            except Exception as e:
                log.warning(f"SIM status report failed: {e}")
            interval = device_config.get("sim_status_interval_seconds", 60)
            shutdown_event.wait(interval)
        log.info("SIM status reporter stopped")

    # Start all threads
    threads = [
        threading.Thread(target=gps_thread_fn,       daemon=True, name="gps"),
        threading.Thread(target=camera_thread_fn,    daemon=True, name="camera"),
        threading.Thread(target=sim_report_thread_fn,daemon=True, name="sim-status"),
    ]
    for t in threads:
        t.start()

    log.info("All services running — waiting for shutdown signal")
    shutdown_event.wait()

    log.info("Shutdown complete")


if __name__ == "__main__":
    main()
