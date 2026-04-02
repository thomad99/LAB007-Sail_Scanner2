"""
Device config manager.
Holds the active configuration and polls the server for updates.
"""

import threading
import time
import copy
import logging

import config as cfg

log = logging.getLogger(__name__)


class DeviceConfig:
    """
    Thread-safe wrapper around the device configuration dict.
    Polls the server periodically; callbacks can be registered.
    """

    def __init__(self, uploader, initial_config=None):
        self._config   = copy.deepcopy(cfg.DEFAULT_CONFIG)
        if initial_config:
            self._config.update(initial_config)
        self._lock     = threading.Lock()
        self._uploader = uploader
        self._callbacks = []   # called(new_cfg) when config changes

    # ── Thread-safe accessors ─────────────────────────────────────────────────

    def get(self, key, default=None):
        with self._lock:
            return self._config.get(key, default)

    def all(self):
        with self._lock:
            return copy.deepcopy(self._config)

    def update(self, new_config):
        if not new_config:
            return
        with self._lock:
            changed = any(self._config.get(k) != v for k, v in new_config.items())
            if changed:
                self._config.update(new_config)
                snapshot = copy.deepcopy(self._config)
        if changed:
            log.info(f"Config updated: {snapshot}")
            for cb in self._callbacks:
                try:
                    cb(snapshot)
                except Exception as e:
                    log.warning(f"Config callback error: {e}")

    def on_change(self, callback):
        """Register a function to call whenever config changes."""
        self._callbacks.append(callback)

    # ── Background polling ────────────────────────────────────────────────────

    def start_polling(self):
        t = threading.Thread(target=self._poll_loop, daemon=True, name="config-poll")
        t.start()

    def _poll_loop(self):
        while True:
            time.sleep(cfg.CONFIG_POLL_SECONDS)
            new = self._uploader.fetch_config()
            if new:
                # Commands are embedded under __commands — strip before storing config
                commands = new.pop("__commands", []) or []
                self.update(new)
                # Fire callbacks with commands included so main.py can act on them
                if commands:
                    for cb in self._callbacks:
                        try:
                            merged = copy.deepcopy(self._config)
                            merged["__commands"] = commands
                            cb(merged)
                        except Exception as e:
                            log.warning(f"Command callback error: {e}")
