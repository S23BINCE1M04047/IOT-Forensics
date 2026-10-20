# IoT Forensic Triage Dashboard: backend

Rule-based, explainable triage of IoT (ESP32) PCAP captures. Every finding links to packet numbers
in the original, unmodified PCAP. Priority means investigation priority, not proof of attack.

## Prerequisites
Python 3.11, Node 18+ (frontend), Wireshark or tcpdump for captures. TShark is optional (PyShark fallback, not used yet).

## Install
```bash
cd backend
python3.11 -m venv .venv && source .venv/bin/activate   # Windows: py -3.11 -m venv .venv; .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/make_sample_pcap.py
```

## Run
```bash
#.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000     # API docs: http://localhost:8000/docs
cd ../frontend && npm install && npm run dev   # UI: http://localhost:5173
```

## Test
```bash
cd backend && pytest -q
```

## Configuration
- Thresholds: `app/services/prioritizer_config.py` (only place to tune; never edit rule logic).
- Whitelist (internal subnets, known endpoints/domains): `data/whitelist.json`
- Threat-intel indicators: `data/threat_intel.csv` (`indicator,type,description,source`, type = ip|domain)
- Environment overrides use the `IFTD_` prefix, e.g. `IFTD_MAX_UPLOAD_MB=500`.
- SQLite is for prototyping only; it is not production-grade.

## Baselines
Analyze a known-good capture, save it as a baseline (UI button or `POST /api/baselines`), then analyze
suspect captures with that baseline selected. Without a baseline, R-PATTERN-DEV-01, R-DNS-NEW-01,
R-DEST-NEW-01 and R-SPIKE-01 are skipped, and R-EXT-DEST-01 runs at reduced confidence.

## How to capture ESP32 traffic
Pick the vantage point first; the capture can only contain what that point can see.
1. **Mirror/SPAN port (best).** Mirror the switch or router port that carries the ESP32's traffic to
   your capture host, then: `sudo tcpdump -i <iface> -w esp32.pcap host <esp32-ip>`
2. **Router/gateway capture.** If the ESP32 is behind your own router (OpenWrt, etc.), run tcpdump on
   the router's LAN/WLAN interface and copy the file out.
3. **Wi-Fi monitor mode.** Put a Wi-Fi adapter in monitor mode on the ESP32's channel
   (`sudo airmon-ng start wlan0 <channel>`, or Wireshark's "Monitor mode" checkbox on macOS/Linux).
   Frames are 802.11; without the network's WPA2 key configured in Wireshark
   (Edit > Preferences > Protocols > IEEE 802.11 > Decryption keys) the payload stays encrypted, and the
   4-way handshake must be captured for decryption to work. Export decrypted traffic before upload if you want IP-level analysis.
4. **Software AP / bridge.** Have the ESP32 join a Linux hotspot you control and capture on the hotspot
   interface; you see all of its traffic.

Upload `.pcap` or `.pcapng`. The tool stores the original untouched (read-only) and hashes it with SHA-256.

## Limitations (read before drawing conclusions)
- On a **switched Wi-Fi/Ethernet network** a capture host normally sees only its own, broadcast and
  multicast traffic, not the ESP32's unicast traffic, unless you use a mirror port, a gateway capture or monitor mode.
- **Encrypted payloads** (TLS, MQTT over TLS, WPA2/3 frames) cannot be read without decryption material.
  Metadata (IPs, ports, timing, sizes, DNS) is still analyzed; payload previews will be empty.
- Rules produce investigation priority. A P1 is a reason to look, not a verdict.