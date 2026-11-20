# THIS MODULE WILL HOUSE PROGRAM WILL CODE



# ETC IMPORTS



# UI IMPORTS
from rich.console import Console





class Variables():
    """Program wide variables"""



    console = Console()


    ip   = False
    port = 8899
    subnet = False
    iface  = False

    poc     = False
    command = False
    scan    = False
    bruteforce = False

    save = False


    endpoints = {
        "camera_feed": "/?action=stream" # PORT 8080
    }


    commands = {
        "~M17":  "Enable stepper motors",
        "~M18":  "Disable stepper motors | Z-axis drop risk",
        "~M20":	 "List stored print files",
        "~M23":  "Select/read file | Path traversal capable",
        "~M25":  "Pause print",
        "~M26":  "Cancel print | DoS via spam",
        "~M27":  "Report print status",
        "~M28":  "Create/write file | Path traversal capable",
        "~M29":  "Stop writing file",
        "~M30":  "Delete file | Path traversal capable",
        "~M81":  "Power off | Unverified on stock 5M Pro firmware",
        "~M104": "Set hotend target temperature | Thermal safety risk",
        "~M105": "Query current and target hotend/bed temperatures",
        "~M106": "Enable part cooling fan | Supports speed parameter",
        "~M107": "Disable part cooling fan",
        "~M108": "Firmware-dependent | Function not confirmed on 5M Pro",
        "~M112": "Emergency stop | Interrupts printer operation",
        "~M113": "Unknown | Not verified on FlashForge 5M Pro",
        "~M114": "Query current axis positions",
        "~M115": "Firmware information | Model, serial, MAC, firmware version",
        "~M116": "Unknown | Not verified on FlashForge 5M Pro",
        "~M119": "Printer status | Endstops, machine state, LEDs, active file",
        "~M120": "Unknown | Not verified on FlashForge 5M Pro",
        "~M140": "Set bed target temperature | Burn hazard",
        "~M146": "Set LED color | RGB + fade",
        "~M601": "Session control | S0=take S1=release",
        "~M610": "Set machine name",
        "~M650": "Query filament info",
        "~M661": "List print files with paths",
        "~M662": "Get file thumbnail PNG",
        "~G28":  "Home all axes | Physical collision risk",
    }
    

    FLASHFORGE_MODELS = {
        0x0004: "Guider 2",
        0x0006: "Inventor 2",
        0x0007: "Finder Plus",
        0x0008: "Adventurer 3",
        0x0009: "Guider 2S",
        0x000D: "Adventurer 3 Lite",
        0x0010: "Creator 4",
        0x0014: "Creator 3 Pro",
        0x0016: "Adventurer 4 Lite",
        0x0017: "Finder 3",
        0x0019: "Guider 3 Plus",
        0x001D: "Adventurer 3 Pro 2",
        0x001E: "Adventurer 4 Pro",
        0x001F: "Guider 3 Ultra",
        0x0023: "Adventurer 5M",
        0x0024: "Adventurer 5M Pro",
        0x0025: "Guider 4",
        0x0026: "Adventurer 5X (AD5X)",
        0x0027: "Guider 4 Pro",
        0x0028: "Creator 5",
        0x0029: "Creator 5 Pro",
    }


    # PATHS THAT CAME BACK WITH SIZE > 0 FROM PATHS LIST
    valid_paths = [

            # Sensitive Files
            "/etc/passwd",
            "/etc/shadow",
            "/etc/wpa_supplicant.conf",
            "/etc/group",
            "/etc/profile",

            # System Configuration
            "/etc/hostname",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/network/interfaces",
            "/etc/fstab",
            "/etc/inittab",
            "/etc/init.d/rcS",
            "/etc/os-release",
            "/etc/issue",
            "/etc/ssl/private",

            # Binaries and Services
            "/bin/busybox",
            "/bin/sh",
            "/sbin/init",
            "/usr/bin/python3",
            "/usr/bin/wget",
            "/usr/bin/telnet",
            "/usr/sbin/wpa_supplicant",
            "/usr/sbin/crond",
            "/usr/sbin/inetd",
            "/proc/self/exe",

            # Network Interfaces
            "/sys/class/net/wlan0/address",
            "/sys/class/net/eth0/address",

            # Logs
            "/var/log/messages"

        ]

    
    # TOOK A WHILE TO GET ALL THESE BUT BOOM, HERE WE ARE WITH ALL 50 PATHS CONFIRMED BY SIZES OF NON ZERO
    paths = [

        # === CONFIRMED HITS (from prior scans) ===
        # /etc/passwd             — 340 bytes
        # /etc/shadow             — 273 bytes (root password hash)
        # /etc/group              — 307 bytes
        # /etc/wpa_supplicant.conf — 59 bytes (WiFi credentials)
        # /etc/hostname           — 6 bytes
        # /etc/hosts              — 36 bytes
        # /etc/resolv.conf        — 62 bytes
        # /etc/network/interfaces — 77 bytes
        # /etc/hostapd.conf       — 188 bytes (AP config)
        # /etc/udhcpd.conf        — 234 bytes (DHCP config)
        # /etc/fstab              — 313 bytes
        # /etc/inittab            — 1,284 bytes
        # /etc/init.d/rcS         — 960 bytes
        # /etc/profile            — 357 bytes
        # /etc/os-release         — 107 bytes
        # /etc/issue              — 37 bytes
        # /etc/fw_env.config      — 64 bytes (U-Boot env)
        # /etc/shells             — 18 bytes
        # /etc/services           — 10,873 bytes
        # /etc/protocols          — 2,744 bytes
        # /opt/private.pem        — 1,743 bytes (RSA key pair)
        # /opt/key.pub            — 451 bytes (RSA public key)
        # /opt/key.priv           — 1,675 bytes (RSA PRIVATE KEY)
        # /opt/openssl-1.0.2d/openssl.cnf — 10,835 bytes
        # /opt/openssl-1.0.2d/bin/openssl  — 495,473 bytes
        # /opt/openssl-1.0.2d/lib/libssl.so    — 349,329 bytes
        # /opt/openssl-1.0.2d/lib/libcrypto.so — 1,559,615 bytes
        # /opt/PROGRAM/ffstartup-arm   — 2,781,568 bytes (startup binary)
        # /opt/PROGRAM/ffstartup.cfg   — 315 bytes (startup config)
        # /opt/config/printer.cfg      — 1,768 bytes (Klipper config)
        # /opt/config/printer.base.cfg — 5,998 bytes (Klipper base config)
        # /opt/klipper/klippy/klippy.py — 15,571 bytes (Klipper host source)
        # /opt/nim/lib/libnim.so       — 5,297,687 bytes (NetEase NIM cloud SDK)
        # /opt/boot.img           — 3,072,000 bytes (boot image)
        # /opt/mencoder           — 20,487,189 bytes (video encoder)
        # /lib/modules/8821cu.ko  — 2,441,368 bytes (WiFi kernel module)
        # /proc/self/exe          — 9,564,802 bytes (firmwareExe binary)
        # /sys/class/net/wlan0/address   — 4,096 bytes (MAC address)
        # /sys/class/net/eth0/address    — 4,096 bytes (MAC address)
        # /sys/class/net/wlan0/operstate — 4,096 bytes
        # /sys/class/net/eth0/operstate  — 4,096 bytes
        # /tmp/resolv.conf        — 62 bytes
        # /var/log/messages       — ~161,005 bytes (growing system log)
        # /var/run/utmp           — 384 bytes
        # /bin/busybox            — 707,572 bytes
        # /bin/sh                 — 602,732 bytes
        # /sbin/init              — 707,572 bytes
        # /usr/bin/wget           — 707,572 bytes

        # === CREDENTIALS & AUTH ===
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/wpa_supplicant.conf",
        "/etc/wpa_supplicant/wpa_supplicant.conf",

        # === NETWORK CONFIG ===
        "/etc/hostname",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/network/interfaces",
        "/etc/NetworkManager/NetworkManager.conf",
        "/etc/hostapd.conf",
        "/etc/hostapd/hostapd.conf",
        "/etc/dnsmasq.conf",
        "/etc/udhcpd.conf",

        # === SYSTEM CONFIG ===
        "/etc/fstab",
        "/etc/inittab",
        "/etc/init.d/rcS",
        "/etc/profile",
        "/etc/os-release",
        "/etc/issue",
        "/etc/version",
        "/etc/build",
        "/etc/fw_env.config",

        # === SSL / CRYPTO ===
        "/etc/ssl/private/server.key",
        "/etc/ssl/certs/server.crt",
        "/etc/ssl/private/ca.key",
        "/opt/private.pem",
        "/opt/key.pub",
        "/opt/key.priv",
        "/opt/openssl-1.0.2d/openssl.cnf",

        # === FLASHFORGE FIRMWARE (from flashforge_init.sh) ===
        "/opt/PROGRAM/ffstartup-arm",
        "/opt/PROGRAM/ffstartup.cfg",
        "/opt/PROGRAM/config.ini",
        "/opt/PROGRAM/config.json",
        "/opt/PROGRAM/config.xml",
        "/opt/PROGRAM/printer.cfg",
        "/opt/PROGRAM/printer.conf",
        "/opt/PROGRAM/machine.conf",
        "/opt/PROGRAM/network.conf",
        "/opt/PROGRAM/cloud.conf",
        "/opt/PROGRAM/cloud.json",
        "/opt/PROGRAM/mqtt.conf",
        "/opt/PROGRAM/mqtt.json",
        "/opt/PROGRAM/oss.conf",
        "/opt/PROGRAM/oss.json",
        "/opt/PROGRAM/auth.json",
        "/opt/PROGRAM/token.json",
        "/opt/PROGRAM/device.json",
        "/opt/PROGRAM/settings.json",
        "/opt/PROGRAM/settings.ini",
        "/opt/PROGRAM/version",
        "/opt/PROGRAM/version.txt",
        "/opt/PROGRAM/update.json",

        # === FLASHFORGE KERNEL/SOFTWARE/CONTROL ===
        "/opt/PROGRAM/kernel/version",
        "/opt/PROGRAM/software/version",
        "/opt/PROGRAM/control/version",
        "/opt/PROGRAM/library/version",

        # === DATA DIR (print files, logs, cloud cache) ===
        "/data/logFiles/firmwareExe",
        "/data/config.ini",
        "/data/config.json",
        "/data/cloud.json",
        "/data/auth.json",
        "/data/token.json",
        "/data/device.json",
        "/data/mqtt.json",
        "/data/settings.json",
        "/data/wifi.conf",
        "/data/wpa.conf",
        "/data/network.json",
        "/data/serial",
        "/data/sn",
        "/data/mac",
        "/data/logFiles/log.txt",
        "/data/logFiles/crash.log",
        "/data/logFiles/app.log",
        "/data/logFiles/system.log",
        "/data/logFiles/mqtt.log",
        "/data/logFiles/cloud.log",
        "/data/logFiles/update.log",
        "/data/logFiles/error.log",

        # === ROOT HOME ===
        "/root/.bash_history",
        "/root/.ash_history",
        "/root/.profile",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_rsa.pub",
        "/root/.ssh/authorized_keys",
        "/root/.ssh/known_hosts",
        "/root/.ssh/config",
        "/root/.bashrc",
        "/root/.wget-hsts",

        # === PROC (runtime state) ===
        "/proc/self/exe",
        "/proc/self/cmdline",
        "/proc/self/environ",
        "/proc/self/maps",
        "/proc/self/status",
        "/proc/self/net/tcp",
        "/proc/self/net/udp",
        "/proc/self/net/arp",
        "/proc/self/net/wireless",
        "/proc/version",
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/proc/mounts",
        "/proc/cmdline",
        "/proc/net/tcp",
        "/proc/net/udp",
        "/proc/net/arp",
        "/proc/net/wireless",
        "/proc/net/route",

        # === SYS (hardware info) ===
        "/sys/class/net/wlan0/address",
        "/sys/class/net/eth0/address",
        "/sys/class/net/wlan0/operstate",
        "/sys/class/net/eth0/operstate",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/product_serial",

        # === TMP (runtime tokens, sockets) ===
        "/tmp/auth_token",
        "/tmp/authToken",
        "/tmp/token",
        "/tmp/mqtt_config",
        "/tmp/cloud_config",
        "/tmp/session",
        "/tmp/wifi.conf",
        "/tmp/resolv.conf",
        "/tmp/wpa_supplicant.conf",
        "/tmp/log.txt",

        # === VAR (logs, state) ===
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/dmesg",
        "/var/log/auth.log",
        "/var/run/wpa_supplicant/wlan0",
        "/var/run/hostapd/wlan0",
        "/var/run/utmp",
        "/var/spool/cron/root",
        "/var/spool/cron/crontabs/root",

        # === BOOT / FIRMWARE ===
        "/opt/boot.img",
        "/opt/screwflag",
        "/opt/mencoder",

        # === BUSYBOX / BINARIES ===
        "/bin/busybox",
        "/bin/sh",
        "/sbin/init",
        "/usr/bin/curl",
        "/usr/bin/wget",
        "/usr/bin/openssl",
        "/usr/sbin/telnetd",
        "/usr/sbin/dropbear",
        "/usr/sbin/sshd",
        "/usr/sbin/ftpd",
        "/usr/sbin/mosquitto",

        # === WIFI DRIVER / MODULES (from auto_run.sh) ===
        "/opt/PROGRAM/8821cu.ko",
        "/lib/modules/8821cu.ko",

        # === FLASHFORGE STARTUP (from auto_run.sh / flashforge_init.sh) ===
        "/opt/PROGRAM/start.img",
        "/opt/PROGRAM/end.img",
        "/opt/PROGRAM/play",
        "/opt/PROGRAM/shadow",
        "/opt/PROGRAM/inittab",
        "/opt/PROGRAM/flashforge_init.sh",
        "/opt/PROGRAM/auto_run.sh",
        "/opt/PROGRAM/run.sh",
        "/opt/PROGRAM/rcS",
        "/opt/PROGRAM/screwflag",
        "/opt/PROGRAM/Cube-PLA-Test.gx",

        # === OPENSSL INSTALL ===
        "/opt/openssl-1.0.2d/bin/openssl",
        "/opt/openssl-1.0.2d/lib/libssl.so",
        "/opt/openssl-1.0.2d/lib/libcrypto.so",
        "/opt/openssl-1.0.2d/certs/ca-bundle.crt",

        # === CLOUD / MQTT RUNTIME (from binary strings) ===
        "/data/logFiles/cloud_config.json",
        "/data/logFiles/mqtt_config.json",
        "/data/logFiles/oss_config.json",
        "/data/logFiles/auth_token",
        "/data/logFiles/device_info.json",
        "/data/logFiles/nimConfig.json",
        "/data/logFiles/appClient.json",

        # === WEB INTERFACE (from firmware client/ dir) ===
        "/opt/PROGRAM/client/Home.html",
        "/opt/PROGRAM/client/Header.html",
        "/opt/PROGRAM/client/w3.css",
        "/data/logFiles/client/Home.html",

        # === NETWORK TOOLS (from firmware network/ dir) ===
        "/opt/PROGRAM/network/hostapd",
        "/opt/PROGRAM/network/iwlist",
        "/opt/PROGRAM/network/wifi_reconnect",

        # === CAMERA / VIDEO ===
        "/data/logFiles/video",
        "/data/logFiles/snapshot.jpg",
        "/data/logFiles/camera.conf",
        "/tmp/snapshot.jpg",
        "/tmp/camera.jpg",
        "/tmp/video.mp4",

        # === DEEPER /data ===
        "/data/logFiles/config.ini",
        "/data/logFiles/config.json",
        "/data/logFiles/settings.json",
        "/data/logFiles/printer.cfg",
        "/data/logFiles/version",
        "/data/Cube-PLA-Test.gx",
        "/data/print_history.json",
        "/data/job_history.json",

        # === PROC (creds in env, open file descriptors) ===
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/proc/self/fd/3",
        "/proc/self/fd/4",
        "/proc/self/fd/5",
        "/proc/self/cgroup",
        "/proc/1/cmdline",
        "/proc/1/environ",

        # === DEV (flash/storage partitions) ===
        "/dev/mtd0",
        "/dev/mtdblock0",
        "/dev/mmcblk0",
        "/dev/mmcblk0p1",
        "/dev/fb0",

        # === KLIPPER (community found on AD5M stock firmware) ===
        "/opt/config/printer.cfg",
        "/opt/config/printer.base.cfg",
        "/opt/config/macros.cfg",
        "/opt/config/gcode_macro.cfg",
        "/opt/config/stepper.cfg",
        "/opt/config/extruder.cfg",
        "/opt/config/fan.cfg",
        "/opt/config/bed_mesh.cfg",
        "/opt/config/resonance.cfg",
        "/opt/config/input_shaper.cfg",
        "/opt/klipper/klippy/klippy.py",
        "/opt/klipper/config/printer.cfg",

        # === KLIPPER LOGS & RUNTIME ===
        "/data/logFiles/printer.log",
        "/data/logFiles/klippy.log",
        "/tmp/klippy.log",
        "/tmp/printer",
        "/tmp/klippy_uds",

        # === MOONRAKER (if Forge-X mod installed) ===
        "/root/printer_data/config/printer.cfg",
        "/root/printer_data/config/moonraker.conf",
        "/root/printer_data/logs/klippy.log",
        "/root/printer_data/logs/moonraker.log",
        "/root/printer_data/database/data.mdb",

        # === FLASHFORGE SOFTWARE DIR (community research) ===
        "/opt/PROGRAM/software/firmwareExe",
        "/opt/PROGRAM/software/version",
        "/opt/PROGRAM/software/run.sh",
        "/opt/PROGRAM/software/ffstartup.cfg",

        # === NETEASE NIM (cloud messaging SDK, from unbrick research) ===
        "/opt/nim/lib/libnim.so",
        "/opt/nim/lib/libnrtc.so",
        "/opt/nim/lib/libnrtc_audio_process.so",
        "/opt/nim/nim.conf",
        "/opt/nim/config.json",

        # === USB MOUNT / MEDIA ===
        "/media/usb/autorun.sh",
        "/media/usb0/autorun.sh",
        "/mnt/usb/autorun.sh",
        "/mnt/udisk/autorun.sh",

        # === DEEPER /data LOGS ===
        "/data/logFiles/firmwareExe.log",
        "/data/logFiles/firmware.log",
        "/data/logFiles/startup.log",
        "/data/logFiles/network.log",
        "/data/logFiles/ota.log",
        "/data/logFiles/ota_update.log",

        # === ADDITIONAL SYSTEM FILES ===
        "/etc/hosts.deny",
        "/etc/hosts.allow",
        "/etc/crontab",
        "/etc/mtab",
        "/etc/shells",
        "/etc/services",
        "/etc/protocols",
        "/etc/ld.so.conf",
        "/etc/ld.so.cache",
        "/etc/sysctl.conf",
        "/etc/inetd.conf",
        "/etc/dropbear/dropbear_rsa_host_key",
        "/etc/dropbear/dropbear_dss_host_key",
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/sshd_config",

        # === FLASHFORGE LIBS & CERTS ===
        "/opt/PROGRAM/lib/libssl.so",
        "/opt/PROGRAM/lib/libcrypto.so",
        "/opt/PROGRAM/lib/libmosquitto.so",
        "/opt/PROGRAM/lib/libpaho-mqtt3c.so",
        "/opt/PROGRAM/lib/libpaho-mqtt3a.so",
        "/opt/PROGRAM/lib/libQt5Core.so",
        "/opt/PROGRAM/lib/libQt5Network.so",
        "/opt/PROGRAM/certs/ca.pem",
        "/opt/PROGRAM/certs/client.pem",
        "/opt/PROGRAM/certs/client.key",

        # === DEEPER PROC ===
        "/proc/self/net/dev",
        "/proc/self/net/if_inet6",
        "/proc/partitions",
        "/proc/filesystems",
        "/proc/mtd",
        "/proc/net/dev",
        "/proc/net/if_inet6",
        "/proc/net/netstat",
        "/proc/sys/net/ipv4/ip_forward",

    ]

