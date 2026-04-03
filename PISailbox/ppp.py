"""
PPP connection manager — used when WiFi is unavailable.
Starts a brief ppp0 connection to flush queued GPS points, then disconnects.
"""
import subprocess
import time
import logging

log = logging.getLogger(__name__)

LOCK_FILE = '/var/lock/LCK..ttyAMA0'


def is_wifi_available():
    """Return True if wlan0 currently carries the default internet route.

    Uses `ip route get 8.8.8.8` which is more reliable than
    `ip route show default dev wlan0` on Pi OS kernels.
    """
    try:
        # Primary: ask the kernel which interface would reach the internet
        r = subprocess.run(
            ['ip', 'route', 'get', '8.8.8.8'],
            capture_output=True, text=True, timeout=5
        )
        if 'dev wlan0' in r.stdout:
            return True

        # Fallback: wlan0 has an IP address assigned
        r2 = subprocess.run(
            ['ip', '-4', 'addr', 'show', 'wlan0'],
            capture_output=True, text=True, timeout=5
        )
        return 'inet ' in r2.stdout

    except Exception:
        return False


def is_ppp_up():
    """Return True if ppp0 interface has an IP address assigned."""
    try:
        r = subprocess.run(
            ['ip', 'addr', 'show', 'ppp0'],
            capture_output=True, text=True, timeout=5
        )
        return 'inet ' in r.stdout
    except Exception:
        return False


def _cleanup_stale():
    """Kill any leftover pppd processes and remove stale lock files."""
    try:
        subprocess.run(['killall', 'pppd'], capture_output=True, timeout=5)
        time.sleep(1)
    except Exception:
        pass
    try:
        import os
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
            log.info(f"PPP: removed stale lock {LOCK_FILE}")
    except Exception:
        pass


def _modem_reset():
    """
    Briefly open the serial port to verify the modem is in AT command mode
    and hang up any active call, then close so pppd can take over.
    """
    import serial as _serial
    PORT  = '/dev/ttyAMA0'
    BAUD  = 115200
    try:
        s = _serial.Serial(PORT, BAUD, timeout=2, rtscts=False, dsrdtr=False)
        time.sleep(0.5)
        s.reset_input_buffer()
        # Hang up / reset
        for cmd in [b'ATH\r\n', b'ATZ\r\n', b'AT\r\n']:
            s.write(cmd); time.sleep(0.8)
            resp = s.read_all().decode(errors='ignore').strip()
            log.info(f"PPP modem-reset [{cmd.strip()}] → {repr(resp)}")
        s.close()
        time.sleep(0.5)
    except Exception as e:
        log.warning(f"PPP: modem reset failed (non-fatal): {e}")


def connect(provider='1nce', timeout=50):
    """
    Start PPP connection. Returns True if ppp0 comes up within timeout.
    Requires /etc/ppp/peers/<provider> WITHOUT the 'persist' option.
    """
    if is_ppp_up():
        log.debug("PPP already connected")
        return True

    _cleanup_stale()
    _modem_reset()   # ensure modem is in AT mode before chat script runs

    log.info(f"PPP: connecting via {provider}…")
    try:
        # Write chat debug to /tmp/ppp-debug.log so we can diagnose failures
        subprocess.run(
            ['pon', provider, 'debug', 'logfile', '/tmp/ppp-debug.log'],
            timeout=10, capture_output=True
        )
    except Exception as e:
        log.warning(f"PPP pon failed: {e}")
        return False

    # Wait for ppp0 to get an IP
    for i in range(timeout // 2):
        if is_ppp_up():
            log.info(f"PPP: connected (took ~{i*2}s)")
            return True
        time.sleep(2)

    # Timed out — dump the debug log so we can see where the chat failed
    try:
        with open('/tmp/ppp-debug.log', 'r', errors='ignore') as f:
            lines = f.readlines()
        # Log last 20 lines of PPP debug output
        for line in lines[-20:]:
            log.warning(f"PPP-debug: {line.rstrip()}")
    except Exception:
        pass

    log.warning(f"PPP: timed out after {timeout}s waiting for ppp0")
    _cleanup_stale()
    return False


def disconnect(provider='1nce'):
    """Bring down the PPP connection cleanly."""
    try:
        subprocess.run(['poff', provider], timeout=10, capture_output=True)
        for _ in range(10):
            if not is_ppp_up():
                break
            time.sleep(1)
        log.info("PPP: disconnected")
    except Exception as e:
        log.warning(f"PPP poff failed: {e}")
    finally:
        # Always clean up so pppd lock does not block next GPS serial open
        _cleanup_stale()
