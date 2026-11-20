# Flashforge Adventurer 5M Pro — Security Research

12 vulnerabilities discovered in the Flashforge Adventurer 5M Pro 3D printer through network testing and firmware analysis.

**Researcher:** NSM Barii
**Firmware tested:** v5.1.7-2.2.3 ([public download](https://flashforge-resource.oss-us-east-1.aliyuncs.com/AD5MP%E5%9B%BA%E4%BB%B6/Adventurer5MPro-5.1.7-2.2.3-20260605.tgz))
**Full details:** [DISCLOSURE.md](DISCLOSURE.md)

---

## Findings

| # | Finding | Severity | CWE |
|---|---------|----------|-----|
| 1 | **Unauthenticated G-code Execution** | CVSS 8.8 | CWE-306 |
| 2 | **Path Traversal — Read/Write/Delete** | CVSS 9.6 | CWE-22 |
| 3 | **UDP Amplification + Serial Leak** | CVSS 7.5 | CWE-406 |
| 4 | **Unauthenticated Camera Stream** | CVSS 7.1 | CWE-306 |
| 5 | **Camera Routed to Chinese RTMP Servers** | CVSS 6.5 | CWE-319 |
| 6 | **Hardcoded Root Password** | CVSS 7.5 | CWE-798 |
| 7 | **Hardcoded WiFi AP Password** | CVSS 6.0 | CWE-798 |
| 8 | **Hardcoded RSA Key Passphrase** | CVSS 6.5 | CWE-798 |
| 9 | **Unsigned Firmware Updates** | CVSS 6.8 | CWE-347 |
| 10 | **LAN Mode Doesn't Protect G-code Port** | CVSS 7.4 | CWE-284 |
| 11 | **Auth Bypass on /notifyWanBind** | CVSS 7.4 | CWE-284 |
| 12 | **Zero Brute Force Protection on Auth** | CVSS 7.4 | CWE-287 |

---

### Finding 1 — Unauthenticated G-code Execution
TCP port 8899 accepts raw G-code from any host with no auth. Attacker can query device info, actuate hardware, and cancel prints. **PoC:** `src/poc.py --poc 1`

### Finding 2 — Path Traversal (Critical)
M23/M28/M30 accept `../../` sequences, allowing read, write, and delete of arbitrary files. 48 paths confirmed readable including `/etc/shadow`. **PoC:** `src/poc.py --poc 4` / `src/poc.py --bruteforce`

### Finding 3 — UDP Amplification + Serial Leak
Port 19000 responds to any 1-byte UDP packet with 280 bytes of device identity including serial number. 280x amplification, no rate limiting. **PoC:** `src/poc.py --poc 3`

### Finding 4 — Unauthenticated Camera Stream
Port 8080 serves live MJPEG with no auth, ignores LAN mode, persists across reboots. **PoC:** `src/poc.py --poc 5`

### Finding 5 — Camera to Chinese Infrastructure
RTMP push/play endpoints hardcoded into firmware pointing to Flashforge servers in China. Includes hardcoded fallback IP in Hangzhou. No cloud account required. See [DISCLOSURE.md](DISCLOSURE.md).

### Finding 6 — Hardcoded Root Password
Firmware ships a static `/etc/shadow` redeployed on every update. Same hash on every unit worldwide. See [DISCLOSURE.md](DISCLOSURE.md).

### Finding 7 — Hardcoded WiFi AP Password
SSID and passphrase compiled into the firmware binary. Same credentials on every unit. See [DISCLOSURE.md](DISCLOSURE.md).

### Finding 8 — Hardcoded RSA Key Passphrase
RSA key pair generated with a 4-character hardcoded passphrase. Private key readable via path traversal. See [DISCLOSURE.md](DISCLOSURE.md).

### Finding 9 — Unsigned Firmware Updates
USB firmware updates run as root with zero signature verification. Physical access = arbitrary code execution. See [DISCLOSURE.md](DISCLOSURE.md).

### Finding 10 — LAN Mode Inconsistency
LAN mode only protects port 8898. Port 8899 (G-code) accepts commands in any mode. See [DISCLOSURE.md](DISCLOSURE.md).

### Finding 11 — /notifyWanBind Auth Bypass
Bypasses both LAN mode and checkCode auth. Only needs the serial number, which is broadcast on UDP 19000. See [DISCLOSURE.md](DISCLOSURE.md).

### Finding 12 — Zero Brute Force Protection
500 wrong checkCode attempts at 110+ req/sec with no throttling, no lockout. Correct code accepted immediately after. See [DISCLOSURE.md](DISCLOSURE.md).

---

## Usage

```bash
pip install -r requirements.txt

# Run specific PoC
python3 src/poc.py --ip <printer_ip> --poc <1-5|all>

# Path traversal bruteforcer
python3 src/poc.py --ip <printer_ip> --bruteforce --save

# Raw G-code
python3 src/poc.py --ip <printer_ip> -b "~M115"

# Scan subnet for printers
python3 src/poc.py --subnet 192.168.1.0/24 -scan
```

---

## Firmware Analysis

Static analysis was performed on the publicly available firmware:

1. Download `.tgz` from Flashforge's CDN
2. `tar -xvf Adventurer5MPro-*.tgz`
3. `strings firmwareExe | grep <pattern>` — extracted API keys, RTMP URLs, cloud endpoints, hardcoded credentials
4. Read shell scripts (`flashforge_init.sh`, `auto_run.sh`) — plaintext bash with hardcoded secrets

See `firmware/SOURCE.txt` for provenance.

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-11-19 | Initial discovery |
| 2026-11-20 | All 12 findings documented, submitted to VulnCheck |
| TBD | CVE IDs assigned |
| TBD | Vendor notification (via VulnCheck coordination) |
| TBD | Public disclosure |
