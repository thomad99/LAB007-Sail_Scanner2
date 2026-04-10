"""
SIM / modem manager for Waveshare SIM7600G-H 4G HAT.
Reads signal strength, operator, network type, ICCID, APN.
Can apply a new APN from server config.
"""

import time
import logging
import re

log = logging.getLogger(__name__)

# Network type codes returned by AT+CNSMOD
NETWORK_TYPES = {
    "0": "No service",
    "1": "GSM",
    "2": "GPRS",
    "3": "EGPRS",
    "4": "WCDMA",
    "5": "HSDPA",
    "6": "HSUPA",
    "7": "HSPA",
    "8": "LTE",
    "9": "TDD-LTE",
    "10": "CDMA",
    "11": "eVDO",
    "12": "Hybrid (CDMA+eVDO)",
}


class SIMManager:
    """
    Reads SIM / modem info and optionally configures APN.
    Shares the GPSReader's serial lock so both can safely use the port.
    """

    def __init__(self, gps_reader):
        """
        gps_reader: an initialised GPSReader whose _send_at() and lock we reuse.
        """
        self._gps = gps_reader

    def _at(self, cmd, wait=1.2):
        return self._gps._send_at(cmd, wait_s=wait)

    # ── Individual queries ────────────────────────────────────────────────────

    def get_signal_strength(self):
        """
        Returns (rssi_raw, rssi_dbm, quality_percent) or (None, None, None).
        AT+CSQ → +CSQ: <rssi>,<ber>
        rssi 0=-113dBm, 31=-51dBm, 99=unknown
        """
        resp = self._at("AT+CSQ", wait=0.8)
        m = re.search(r"\+CSQ:\s*(\d+),", resp)
        if not m:
            return None, None, None
        rssi = int(m.group(1))
        if rssi == 99:
            return 99, None, None
        dbm = -113 + rssi * 2
        pct = round(min(rssi / 31.0 * 100, 100))
        return rssi, dbm, pct

    def get_operator(self):
        """
        Returns operator name string or None.
        AT+COPS? → +COPS: <mode>,<format>,"<operator>",<act>
        """
        resp = self._at("AT+COPS?", wait=1.0)
        m = re.search(r'\+COPS: \d+,\d+,"([^"]+)"', resp)
        return m.group(1) if m else None

    def get_network_type(self):
        """
        Returns human-readable network type string (e.g. "LTE") or None.
        AT+CNSMOD? → +CNSMOD: <stat>,<n>
        """
        resp = self._at("AT+CNSMOD?", wait=0.8)
        m = re.search(r"\+CNSMOD: \d+,(\d+)", resp)
        if m:
            return NETWORK_TYPES.get(m.group(1), f"Type {m.group(1)}")
        return None

    def get_imei(self):
        """Returns modem IMEI or None. AT+CGSN"""
        resp = self._at("AT+CGSN", wait=0.8)
        lines = [l.strip() for l in resp.splitlines() if l.strip() and l.strip() not in ("OK", "AT+CGSN")]
        return lines[0] if lines else None

    def get_registration(self):
        """
        Returns (status_code, status_text).
        AT+CGREG? → +CGREG: <n>,<stat>
        stat: 0=not reg, 1=reg home, 2=searching, 3=denied, 5=roaming
        """
        resp = self._at("AT+CGREG?", wait=0.8)
        codes = {"0": "Not registered", "1": "Registered (home)",
                 "2": "Searching…",     "3": "Denied",
                 "5": "Roaming"}
        m = re.search(r"\+CGREG: \d+,(\d+)", resp)
        if m:
            code = m.group(1)
            return code, codes.get(code, f"Unknown ({code})")
        return None, "Unknown"

    def get_apn(self):
        """
        Returns the first active APN string or None.
        AT+CGDCONT? → +CGDCONT: 1,"IP","internet",...
        """
        resp = self._at("AT+CGDCONT?", wait=0.8)
        m = re.search(r'\+CGDCONT: \d+,"[^"]+","([^"]*)"', resp)
        return m.group(1) if m else None

    def get_ip_address(self):
        """
        Returns the modem-assigned IP address or None.
        AT+CGPADDR → +CGPADDR: 1,<ip>
        """
        resp = self._at("AT+CGPADDR", wait=0.8)
        m = re.search(r"\+CGPADDR: \d+,([0-9.]+)", resp)
        return m.group(1) if m else None

    # ── Composite status snapshot ─────────────────────────────────────────────

    def get_status(self):
        """
        Returns a dict with all SIM/modem info for upload to the server.
        Gracefully handles any individual query failure.
        """
        def safe(fn):
            try: return fn()
            except Exception as e:
                log.debug(f"SIM query failed: {e}")
                return None

        rssi, dbm, pct = safe(self.get_signal_strength) or (None, None, None)
        reg_code, reg_text = safe(self.get_registration) or (None, "Unknown")

        return {
            "signal_rssi":    rssi,
            "signal_dbm":     dbm,
            "signal_percent": pct,
            "operator":       safe(self.get_operator),
            "network_type":   safe(self.get_network_type),
            "registration":   reg_text,
            "registered":     reg_code in ("1", "5"),
            "roaming":        reg_code == "5",
            "iccid":          safe(self.get_iccid),
            "imei":           safe(self.get_imei),
            "apn_active":     safe(self.get_apn),
            "ip_address":     safe(self.get_ip_address),
        }

    # ── APN configuration ─────────────────────────────────────────────────────

    def get_iccid(self):
        """Returns SIM ICCID. Try both AT+CCID and AT+ICCID."""
        for cmd in ["AT+CCID", "AT+ICCID", "AT+CICCID"]:
            resp = self._at(cmd, wait=0.8)
            m = re.search(r'[\+]?(?:CCID|ICCID):\s*([0-9A-Fa-fF]+)', resp)
            if m:
                return m.group(1)
            # Some firmware just returns the ICCID on its own line
            lines = [l.strip() for l in resp.splitlines()
                     if l.strip() and l.strip() not in ("OK",) and not l.startswith("AT+")]
            if lines and re.match(r'^[0-9]{15,20}', lines[0]):
                return lines[0]
        return None

    def apply_apn(self, apn, user="", password=""):
        """
        Set the PDP context APN and reconnect.
        Call this when the server config provides a new APN.
        """
        if not apn:
            return
        log.info(f"Applying APN: {apn} (user={user!r})")
        # Deactivate existing context
        self._at("AT+CGACT=0,1", wait=2)
        # Set new APN
        if user:
            self._at(f'AT+CGDCONT=1,"IP","{apn}"', wait=1)
            self._at(f'AT+CGAUTH=1,1,"{password}","{user}"', wait=1)
        else:
            self._at(f'AT+CGDCONT=1,"IP","{apn}"', wait=1)
        # Reactivate
        self._at("AT+CGACT=1,1", wait=5)
        log.info("APN applied")
