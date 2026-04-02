# PiSailBox

GPS tracker & camera logger for **Raspberry Pi 3B** with:
- **Waveshare SIM7600G-H 4G/GNSS HAT** — cellular data + GPS
- **Raspberry Pi Camera Module 3 Wide** — photos and video

On boot the Pi registers itself with the Love Sailing website, starts GPS tracking (uploading a point every N seconds over 4G), and optionally captures photos on a schedule. Photos are batched and uploaded to save SIM data. Videos are recorded locally only.

---

## Hardware setup

| Component | Connection |
|---|---|
| SIM7600G-H HAT | GPIO header on top of Pi |
| SIM card | Inserted in HAT SIM slot |
| Camera Module 3 | CSI ribbon cable |

Power the Pi **after** inserting the SIM card.

---

## First-time install

### 1. Copy files to the Pi

From your laptop, copy the `pisailbox` folder to the Pi:

```bash
scp -r pisailbox/ pi@<PI_IP_ADDRESS>:~/pisailbox/
```

### 2. Set your server URL

Edit `pisailbox/config.py` and change:
```python
SERVER_URL = "https://lovesailing.ai"
```

Or pass it as an environment variable during install:
```bash
PISAILBOX_SERVER=https://lovesailing.ai sudo bash install.sh
```

### 3. Run the install script

SSH into the Pi and run:

```bash
cd ~/pisailbox
chmod +x install.sh
sudo bash install.sh
```

The installer will:
1. Install system packages (`python3-picamera2`, `ffmpeg`, `modemmanager`, etc.)
2. Enable the camera interface
3. Add `pi` user to the `dialout` group (serial port access)
4. Configure ModemManager for the 4G HAT
5. Copy files to `/opt/pisailbox/`
6. Install and start the `pisailbox` systemd service (auto-starts on every boot)

---

## 4G APN configuration

If the SIM card does not connect automatically, set the APN manually:

```bash
sudo nmcli connection add type gsm ifname '*' con-name pisailbox-4g apn YOUR_APN_HERE
sudo nmcli connection up pisailbox-4g
```

Common APNs:
| UK Network | APN |
|---|---|
| Three | 3internet |
| Vodafone | internet |
| EE | everywhere |
| Hologram (IoT SIM) | hologram |

---

## GPS serial port

The SIM7600G-H HAT uses `/dev/ttyUSB2` for AT commands by default.  
If GPS is not found, check which port the modem is on:

```bash
ls /dev/ttyUSB*
```

Then update `GPS_SERIAL_PORT` in `config.py` (and reinstall) or set the environment variable:

```bash
GPS_PORT=/dev/ttyUSB1 sudo systemctl restart pisailbox
```

---

## Monitoring

```bash
# Live log output
sudo journalctl -u pisailbox -f

# Service status
sudo systemctl status pisailbox

# Application log file
tail -f ~/pisailbox_data/pisailbox.log

# Stored photos (before upload)
ls ~/pisailbox_data/photos/

# Stored videos (local only)
ls ~/pisailbox_data/videos/
```

---

## Control panel (web)

Once the Pi is running and connected, visit:

```
https://lovesailing.ai/PiControl.html
```

From here you can:
- See the device online/offline status
- Configure GPS poll rate, camera settings, video schedule
- View uploaded photos
- Link through to the Tracker Dashboard for live GPS map

---

## File structure

```
pisailbox/
├── main.py         — entry point, starts all threads
├── config.py       — server URL, device ID, defaults
├── gps.py          — SIM7600 GPS via serial AT commands
├── camera.py       — picamera2 photo & video capture
├── uploader.py     — HTTP client + offline queue (SQLite)
├── device.py       — config polling & change callbacks
├── pisailbox.service — systemd unit file
├── install.sh      — one-shot setup script
├── uninstall.sh    — cleanup script
└── requirements.txt
```

---

## Data flow

```
Pi GPS (GNSS) ──AT commands──► gps.py ──► uploader.py ──4G──► /api/tracks/:id/points
                                                                       │
                                                            Tracker Dashboard (live map)

Pi Camera ──► camera.py ──► ~/pisailbox_data/photos/
                                     │
              (every N minutes) ──► uploader.py ──4G──► /api/pi/devices/:id/photos
                                                                │
                                                       PiControl.html (gallery)

Pi Camera (video) ──► ~/pisailbox_data/videos/  (local only, retrieve via SSH)
```
