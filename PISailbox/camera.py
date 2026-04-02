"""
Camera handler for Raspberry Pi Camera Module 3 Wide.
Uses picamera2 (bundled with Pi OS 64-bit).
Photos are saved locally; videos stay local only.
"""

import os
import io
import time
import datetime
import logging
import threading

log = logging.getLogger(__name__)

try:
    from picamera2 import Picamera2
    from picamera2.encoders import H264Encoder
    from picamera2.outputs import FfmpegOutput
    PICAMERA2_AVAILABLE = True
except ImportError:
    PICAMERA2_AVAILABLE = False
    log.warning("picamera2 not available — camera disabled")


class CameraHandler:
    """
    Manages photo and video capture.
    Photos are saved to photos_dir and queued for upload.
    Videos are saved to videos_dir (local only, not uploaded).
    """

    def __init__(self, photos_dir, videos_dir, upload_queue):
        self.photos_dir   = photos_dir
        self.videos_dir   = videos_dir
        self.upload_queue = upload_queue  # list to append (filepath, gps_fix) tuples
        self._cam         = None
        self._lock        = threading.Lock()
        os.makedirs(photos_dir, exist_ok=True)
        os.makedirs(videos_dir, exist_ok=True)

    def _get_camera(self):
        if not PICAMERA2_AVAILABLE:
            return None
        if self._cam is None:
            try:
                self._cam = Picamera2()
            except Exception as e:
                log.error(f"Camera init failed: {e}")
        return self._cam

    # ── Photos ────────────────────────────────────────────────────────────────

    def capture_photo(self, gps_fix=None):
        """Capture a single JPEG and queue it for upload. Returns filepath or None."""
        if not PICAMERA2_AVAILABLE:
            return None

        with self._lock:
            cam = self._get_camera()
            if cam is None:
                return None
            try:
                config = cam.create_still_configuration(
                    main={"size": (1920, 1080)},
                    lores={"size": (640, 480)},
                    display="lores"
                )
                cam.configure(config)
                cam.start()
                time.sleep(1.5)  # let AWB settle

                ts  = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                fname = f"photo_{ts}.jpg"
                fpath = os.path.join(self.photos_dir, fname)
                cam.capture_file(fpath)
                cam.stop()

                log.info(f"Photo captured: {fpath}")
                self.upload_queue.append((fpath, gps_fix))
                return fpath
            except Exception as e:
                log.error(f"Photo capture failed: {e}")
                try: cam.stop()
                except Exception: pass
                return None

    def run_photo_session(self, interval_seconds, session_minutes, get_gps_fix):
        """
        Take photos every interval_seconds for session_minutes.
        get_gps_fix is a callable that returns the current GPSFix or None.
        """
        log.info(f"Starting photo session: every {interval_seconds}s for {session_minutes}min")
        deadline = time.time() + session_minutes * 60
        while time.time() < deadline:
            fix = get_gps_fix()
            self.capture_photo(gps_fix=fix)
            time.sleep(interval_seconds)
        log.info("Photo session complete")

    # ── Video ─────────────────────────────────────────────────────────────────

    def record_video(self, duration_seconds):
        """
        Record an H.264 video for duration_seconds.
        Saved locally only — not uploaded (saves SIM data).
        Returns filepath or None.
        """
        if not PICAMERA2_AVAILABLE:
            return None

        with self._lock:
            cam = self._get_camera()
            if cam is None:
                return None
            try:
                ts    = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                fname = f"video_{ts}.mp4"
                fpath = os.path.join(self.videos_dir, fname)

                config  = cam.create_video_configuration(
                    main={"size": (1280, 720)}
                )
                cam.configure(config)
                encoder = H264Encoder(bitrate=4_000_000)
                output  = FfmpegOutput(fpath)

                cam.start_recording(encoder, output)
                log.info(f"Recording video: {fpath} for {duration_seconds}s")
                time.sleep(duration_seconds)
                cam.stop_recording()
                log.info(f"Video saved: {fpath} ({os.path.getsize(fpath)//1024} KB)")
                return fpath
            except Exception as e:
                log.error(f"Video recording failed: {e}")
                try: cam.stop_recording()
                except Exception: pass
                return None

    def close(self):
        if self._cam:
            try:
                self._cam.close()
            except Exception:
                pass
            self._cam = None
