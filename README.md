# ESP32-MicroADB 📱⚡

The first complete, standalone **Dual-Mode Android Debug Bridge (ADB) Host** for the ESP32-S3 microcontroller.

Seamlessly bridge Android devices over **physical USB-OTG** or **high-speed Wi-Fi** with native support for modern **Android 11+ SPAKE2 Wireless Pairing**, legacy **port 5555 TCP/IP auto-discovery**, and hardware codename detection.

---

## 🌟 Key Features

- **Android 11+ Wireless Pairing (SPAKE2 + TLS 1.3):**
  - First-ever embedded microcontroller port of AOSP's wireless pairing protocol.
  - Full implementation of SPAKE2 key exchange over Curve25519 with RFC 5705 Keying Material Exporters using wolfSSL.
  - Pair using standard 6-digit Wi-Fi pairing codes directly from Android's *Developer options -> Wireless debugging*.
- **Classic TCP/IP Port 5555 Auto-Discovery:**
  - Fast subnet scanner (`1..254`) and gateway detection for Android 4.4 through Android 15.
  - Automatic banner querying and hardware codename extraction (e.g. `olive`, `RE6070L1`, `RMX3950`).
  - Interactive multi-device switcher (`devices`, `connect 1`, `connect 2`).
- **Physical USB-OTG Host:**
  - Hardware USB Host mode using the ESP32-S3 native USB peripheral (GPIO 19/20).
  - Full packet and stream abstraction allowing instant toggling between USB and Wi-Fi modes.
- **Interactive Built-in Shell:**
  - Serial CLI (`adb(wifi)>` / `adb(usb)>`) for running shell commands (`getprop`, `pm list packages`, `input keyevent`, etc.).
  - Hardware BOOT button support: Short press toggles mode (Wi-Fi ⟷ USB); long press initiates wireless pairing.

---

## 🛠️ Hardware Requirements

- **ESP32-S3 DevKitC-1** (or compatible ESP32-S3 board with native USB-OTG support, 8MB/16MB Flash).
- For USB-OTG mode: A USB-OTG cable/adapter and external 5V VBUS power to supply the connected Android phone.

### Pinout (USB-OTG Host)
| ESP32-S3 Pin | Function | Connect to USB Port |
| :--- | :--- | :--- |
| **GPIO 19** | USB D- | Phone USB D- |
| **GPIO 20** | USB D+ | Phone USB D+ |
| **GND** | Ground | Phone USB GND |
| **5V / VBUS** | Power | 5V Power Supply (min 1A) |
| **GPIO 0** | BOOT Button | On-board button (Mode toggle & pairing) |

---

## 🚀 Getting Started

### 1. Clone & Set Up Keys

```bash
git clone https://github.com/<your-username>/esp32-adb-dual-host.git
cd esp32-adb-dual-host
```

Copy the keys template:
```bash
cp include/adb_keys.example.h include/adb_keys.h
```

You can either copy your existing ADB keys from your computer (`~/.android/adbkey` and `~/.android/adbkey.pub`) into `include/adb_keys.h`, or generate a fresh RSA keypair:
```bash
# Generate 2048-bit RSA private key
openssl genrsa -out adbkey 2048

# Generate self-signed certificate for pairing
openssl req -new -x509 -key adbkey -out adbkey.crt -days 36500 -subj "/CN=ADB Key/"
```

### 2. Build and Flash

Built using [PlatformIO](https://platformio.org/):

```bash
# Build firmware
pio run

# Flash to ESP32-S3
pio run -t upload

# Open Serial Monitor (115200 baud)
pio device monitor -b 115200
```

---

## 📖 Usage & Commands

Connect your serial monitor at **115200 baud**.

```text
========================================
  ESP32-S3 Dual-Mode ADB Host           
  (Wireless Wi-Fi + Wired USB-OTG)      
========================================

Commands:
  scan                 - Scan subnet for ADB devices and select device
  devices              - List discovered ADB devices from previous scan
  connect              - Reconnect to phone or auto-discover on 5555
  connect <#|ip[:port]>- Connect to device # (e.g. connect 2) or IP
  pair                 - Start Android 11+ wireless pairing (PIN code)
  wifi                 - Connect to Wi-Fi or show status
  wifi rescan          - Scan and connect to a different Wi-Fi
  mode / usb / wifi    - Switch transport mode (USB-OTG vs Wi-Fi)
  help                 - Show this help menu
  <adb command>        - Run ADB shell command (e.g. getprop, pm list packages)

Hardware Buttons:
  [BOOT] Short Click   - Toggle Wi-Fi / USB mode
  [BOOT] Long Hold     - Start wireless pairing
```

### Android 11+ Wireless Debugging Pairing
1. On your phone, go to **Settings -> Developer options -> Wireless debugging**.
2. Tap **Pair device with pairing code**.
3. In the ESP32 terminal, type `pair` (or hold the BOOT button for 2 seconds).
4. Enter the phone's IP, pairing port, and 6-digit PIN code.
5. The ESP32 completes the SPAKE2 exchange and connects automatically.

### Multi-Device Selection (Port 5555)
When multiple phones are on the network with port 5555 open:
```text
==================================================
  Multiple ADB Devices Found (2 devices)
==================================================
  [1] 10.129.214.94:5555  -  RE6070L1 - RMX3950 [CONNECTED]
  [2] 10.129.214.45:5555  -  olive - Redmi 8
--------------------------------------------------
Select device (1 - 2, or 'r' to rescan) [default 1 in 15s]: 
```
Type `1` or `2` to select, or use `connect 2` anytime to switch between phones.

---

## 🔒 Security Notice

- `include/adb_keys.h` is git-ignored by default. **Never commit your personal private keys or production certificates.**
- NVS credentials and raw flash memory backups are excluded via `.gitignore`.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
