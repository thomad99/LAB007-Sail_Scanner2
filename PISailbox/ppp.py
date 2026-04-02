"""
PPP connection manager — used when WiFi is unavailable.
Starts a brief ppp0 connection to flush queued GPS points, then disconnects.
"""
import subprocess
import time
import logging

log = logging.getLogger(__name__)


def is_wifi_available():
    """Return True if wlan0 has a default route (WiFi internet is up)."""
    try:
        r = subprocess.run(
            ['ip', 'route', 'show', 'default', 'dev', 'wlan0'],
            capture_output=True, text=True, timeout=5
        )
        return bool(r.stdout.strip())
    except Exception:
        return False


def is_ppp_up():
    """Return True if ppp0 interface is up with an IP address."""
    try:
        r = subprocess.run(
            ['ip', 'addr', 'show', 'ppp0'],
            capture_output=True, text=True, timeout=5
        )
        return 'inet ' in r.stdout
    except Exception:
        return False


def connect(provider='1nce', timeout=45):
    """
    Start PPP connection. Returns True if ppp0 comes up within timeout.
    Requires /etc/ppp/peers/<provider> to be configured.
    """
    if is_ppp_up():
        log.debug("PPP already connected")
        return True

    log.info(f"PPP: connecting via {provider}...")
    try:
        subprocess.run(['pon', provider], timeout=10,
                       capture_output=True)
    except Exception as e:
        log.warning(f"PPP pon failed: {e}")
        return False

    # Wait for ppp0 to get an IP
    for _ in range(timeout // 2):
        if is_ppp_up():
            log.info("PPP: connected")
            return True
        time.sleep(2)

    log.warning("PPP: timed out waiting for connection")
    return False


def disconnect(provider='1nce'):
    """Bring down the PPP connection."""
    try:
        subprocess.run(['poff', provider], timeout=10,
                       capture_output=True)
        # Wait briefly for the interface to drop
        for _ in range(10):
            if not is_ppp_up():
                break
            time.sleep(1)
        log.info("PPP: disconnected")
    except Exception as e:
        log.warning(f"PPP poff failed: {e}")
