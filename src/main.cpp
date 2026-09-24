#include <Arduino.h>
#include <WiFi.h>
#include <vector>
#include <esp_random.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <wolfssl.h>
#include "usb_adb_host.h"
#include "adb_pairing.h"
#include <Preferences.h>
#include <nvs_flash.h>
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"
#include "esp_private/brownout.h"

// =========================================================================
// ADB Keys (Loaded from include/adb_keys.h, with fallback to template)
// =========================================================================
#if __has_include("adb_keys.h")
#include "adb_keys.h"
#else
#include "adb_keys.example.h"
#endif

// =========================================================================
// ADB Protocol Constants
// =========================================================================
#define A_CNXN 0x4e584e43
#define A_AUTH 0x48545541
#define A_OPEN 0x4e45504f
#define A_OKAY 0x59414b4f
#define A_CLSE 0x45534c43
#define A_WRTE 0x45545257
#define A_STLS 0x534c5453

#define ADB_AUTH_TOKEN        1
#define ADB_AUTH_SIGNATURE    2
#define ADB_AUTH_RSAPUBLICKEY 3

#define A_VERSION             0x01000000
#define A_STLS_VERSION        0x01000000
#define MAX_PAYLOAD           4096
const uint16_t ADB_PORT = 5555;

struct __attribute__((packed)) AdbMessage {
    uint32_t command;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t data_length;
    uint32_t data_check;
    uint32_t magic;
};

enum AdbTransportMode {
    MODE_WIRELESS,
    MODE_USB_OTG
};

// =========================================================================
// Global State
// =========================================================================
AdbTransportMode currentMode = MODE_WIRELESS;
WiFiClient adbClient;
WOLFSSL_CTX* adbTlsCtx = NULL;
WOLFSSL* adbTlsSsl = NULL;
bool adbUseTls = false;
mbedtls_pk_context pk_ctx;
bool adbAuthenticated = false;
uint32_t stream_local_id = 1;
IPAddress currentPhoneIP;
IPAddress discoverAdbDevice();
bool performAdbHandshake();
bool signChallengeToken(const uint8_t* token, size_t token_len, uint8_t* sig_out);

struct AdbDiscoveredDevice {
    IPAddress ip;
    uint16_t port;
    String model;
    String codename;
    String name;
    String marketname;
    String brand;
    String displayName;
    bool authorized;
};

std::vector<AdbDiscoveredDevice> lastDiscoveredDevices;
void parseAdbBanner(const String& banner, String& model, String& codename, String& name);
String formatDeviceDisplayName(const String& model, const String& codename, const String& marketname, const String& brand);

static int esp_rng_wrapper(void* ctx, unsigned char* out, size_t len) {
    esp_fill_random(out, len);
    return 0;
}

// Interactive Serial read with BOOT button (GPIO 0) monitoring
// Returns "__BOOT_SHORT__" on short press (< 1.5s) to toggle mode
// Returns "__BOOT_LONG__" on long press (>= 1.5s) to initiate pairing
// Optional timeout_ms: returns "__TIMEOUT__" if no input within timeout
String readLine(bool echo = true, uint32_t timeout_ms = 0) {
    String str = "";
    unsigned long startMs = millis();
    while (true) {
        if (timeout_ms > 0 && (millis() - startMs >= timeout_ms)) {
            return "__TIMEOUT__";
        }

        // Monitor physical BOOT button (GPIO 0, active LOW with pullup)
        if (digitalRead(BOOT_PIN) == LOW) {
            delay(50); // debounce
            if (digitalRead(BOOT_PIN) == LOW) {
                unsigned long pressStart = millis();
                while (digitalRead(BOOT_PIN) == LOW) {
                    delay(10);
                }
                unsigned long duration = millis() - pressStart;
                if (duration >= 1500) {
                    if (echo) Serial.println("\n[BOOT] Long press (>= 1.5s) detected: Starting ADB Pairing...");
                    return "__BOOT_LONG__";
                } else {
                    if (echo) Serial.println("\n[BOOT] Short press (< 1.5s) detected: Toggling Mode...");
                    return "__BOOT_SHORT__";
                }
            }
        }

        if (Serial.available()) {
            char c = Serial.read();
            if (c == '\r' || c == '\n') {
                delay(5);
                if (Serial.available()) {
                    char next = Serial.peek();
                    if (next == '\n' || next == '\r') {
                        Serial.read();
                    }
                }
                if (echo) Serial.println();
                return str;
            }
            if (c == '\b' || c == 0x7F) {
                if (str.length() > 0) {
                    str.remove(str.length() - 1);
                    if (echo) Serial.print("\b \b");
                }
            } else if (c >= 32 && c <= 126) {
                str += c;
                if (echo) Serial.print(c);
                timeout_ms = 0;
            }
        }
        delay(5);
    }
}

// =========================================================================
// TLS 1.3 Setup & Disconnect for Android Wireless Debugging
// =========================================================================
bool setupAdbTls() {
    if (adbTlsSsl) {
        wolfSSL_free(adbTlsSsl);
        adbTlsSsl = NULL;
    }
    if (adbTlsCtx) {
        wolfSSL_CTX_free(adbTlsCtx);
        adbTlsCtx = NULL;
    }

    adbTlsCtx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!adbTlsCtx) {
        Serial.println("[TLS] Failed to create wolfSSL CTX");
        return false;
    }
    wolfSSL_CTX_set_verify(adbTlsCtx, WOLFSSL_VERIFY_NONE, NULL);

    if (wolfSSL_CTX_use_certificate_buffer(adbTlsCtx, (const unsigned char*)ADB_CERT_PEM,
                                           strlen(ADB_CERT_PEM), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        Serial.println("[TLS] Failed to load host certificate");
        return false;
    }
    if (wolfSSL_CTX_use_PrivateKey_buffer(adbTlsCtx, (const unsigned char*)ADB_PRIVATE_KEY_PEM,
                                          strlen(ADB_PRIVATE_KEY_PEM), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        Serial.println("[TLS] Failed to load private key");
        return false;
    }

    adbTlsSsl = wolfSSL_new(adbTlsCtx);
    if (!adbTlsSsl) {
        Serial.println("[TLS] Failed to allocate wolfSSL session");
        return false;
    }

    wolfSSL_set_fd(adbTlsSsl, adbClient.fd());
    Serial.println("[TLS] Performing TLS 1.3 handshake over ADB connection...");
    if (wolfSSL_connect(adbTlsSsl) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(adbTlsSsl, 0);
        Serial.printf("[TLS] Handshake failed (err=%d)\n", err);
        return false;
    }
    Serial.println("[TLS] TLS 1.3 handshake SUCCESSFUL!");
    adbUseTls = true;
    return true;
}

void disconnectAdbWireless() {
    if (adbTlsSsl) {
        wolfSSL_free(adbTlsSsl);
        adbTlsSsl = NULL;
    }
    if (adbTlsCtx) {
        wolfSSL_CTX_free(adbTlsCtx);
        adbTlsCtx = NULL;
    }
    adbUseTls = false;
    if (adbClient.connected()) {
        adbClient.stop();
    }
}

// =========================================================================
// Transport Layer (Unified Wireless TCP/TLS vs Wired USB-OTG)
// =========================================================================
bool rawWrite(const uint8_t* data, size_t len) {
    if (currentMode == MODE_WIRELESS) {
        if (!adbClient.connected()) return false;
        if (adbUseTls && adbTlsSsl) {
            int ret = wolfSSL_write(adbTlsSsl, data, len);
            return (ret == (int)len);
        } else {
            size_t written = adbClient.write(data, len);
            adbClient.flush();
            return (written == len);
        }
    } else {
        return UsbAdbHost::writeData(data, len);
    }
}

int rawRead(uint8_t* buf, size_t len, uint32_t timeout_ms = 4000) {
    if (currentMode == MODE_WIRELESS) {
        unsigned long start = millis();
        size_t total = 0;
        while (total < len && (millis() - start < timeout_ms)) {
            if (adbUseTls && adbTlsSsl) {
                int n = wolfSSL_read(adbTlsSsl, buf + total, len - total);
                if (n > 0) {
                    total += n;
                    start = millis();
                } else {
                    int err = wolfSSL_get_error(adbTlsSsl, n);
                    if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
                        break;
                    }
                    delay(2);
                }
            } else {
                if (adbClient.available()) {
                    total += adbClient.readBytes((char*)(buf + total), len - total);
                }
                delay(2);
            }
        }
        return total;
    } else {
        return UsbAdbHost::readData(buf, len, timeout_ms);
    }
}

bool rawConnected() {
    if (currentMode == MODE_WIRELESS) {
        return adbClient.connected();
    } else {
        return UsbAdbHost::isAdbReady();
    }
}

void sendPacket(uint32_t cmd, uint32_t arg0, uint32_t arg1, const uint8_t* payload, uint32_t len) {
    AdbMessage msg;
    msg.command = cmd;
    msg.arg0 = arg0;
    msg.arg1 = arg1;
    msg.data_length = len;
    
    uint32_t sum = 0;
    if (payload && len > 0) {
        for (uint32_t i = 0; i < len; i++) {
            sum += payload[i];
        }
    }
    msg.data_check = sum;
    msg.magic = cmd ^ 0xFFFFFFFF;

    rawWrite((const uint8_t*)&msg, sizeof(msg));
    if (payload && len > 0) {
        rawWrite(payload, len);
    }
}

bool signChallengeToken(const uint8_t* token, size_t token_len, uint8_t* sig_out) {
    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk_ctx);
    if (!rsa) return false;

    int ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(
        rsa,
        esp_rng_wrapper,
        NULL,
        MBEDTLS_MD_SHA1,
        (unsigned int)token_len,
        token,
        sig_out
    );
    return (ret == 0);
}

// =========================================================================
// ADB Session Handshake (Works for both Wi-Fi & USB)
// =========================================================================
bool performAdbHandshake() {
    Serial.println("[ADB] Initiating A_CNXN handshake...");
    const char* banner = "host::features=cmd\0";
    sendPacket(A_CNXN, A_VERSION, MAX_PAYLOAD, (const uint8_t*)banner, strlen(banner) + 1);

    unsigned long startMs = millis();
    bool sig_sent = false;
    bool pubkey_sent = false;

    while (rawConnected() && (millis() - startMs < 20000)) {
        AdbMessage resp;
        int n = rawRead((uint8_t*)&resp, sizeof(AdbMessage), 500);
        if (n == sizeof(AdbMessage)) {
            if (resp.magic != (resp.command ^ 0xFFFFFFFF)) {
                Serial.println("[ADB] Invalid packet magic.");
                return false;
            }

            if (resp.command == A_STLS) {
                Serial.println("[ADB] Device requested TLS 1.3 handshake (A_STLS)...");
                sendPacket(A_STLS, A_STLS_VERSION, 0, NULL, 0);
                if (!setupAdbTls()) {
                    Serial.println("[ADB] Failed to establish TLS 1.3 session.");
                    return false;
                }
                Serial.println("[ADB] Resending A_CNXN over TLS session...");
                sendPacket(A_CNXN, A_VERSION, MAX_PAYLOAD, (const uint8_t*)banner, strlen(banner) + 1);
                startMs = millis();
            }
            else if (resp.command == A_AUTH && resp.arg0 == ADB_AUTH_TOKEN) {
                uint8_t token[resp.data_length];
                rawRead(token, resp.data_length, 2000);

                if (!sig_sent) {
                    uint8_t sig[256];
                    if (signChallengeToken(token, resp.data_length, sig)) {
                        Serial.println("[ADB] Authenticating with private key signature...");
                        sendPacket(A_AUTH, ADB_AUTH_SIGNATURE, 0, sig, 256);
                        sig_sent = true;
                    } else {
                        Serial.println("[ADB] Signature failed. Sending public key...");
                        sendPacket(A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, 
                                   (const uint8_t*)ADB_PUBLIC_KEY, strlen(ADB_PUBLIC_KEY) + 1);
                        pubkey_sent = true;
                    }
                } else if (!pubkey_sent) {
                    // Signature was rejected by phone. Phone sends second token requesting public key.
                    Serial.println("[ADB] Key not yet recognized by device.");
                    Serial.println("[ADB] Sending Public Key -> CHECK PHONE SCREEN AND TAP 'ALLOW'!");
                    sendPacket(A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, 
                               (const uint8_t*)ADB_PUBLIC_KEY, strlen(ADB_PUBLIC_KEY) + 1);
                    pubkey_sent = true;
                    startMs = millis(); // Reset timeout to give user 20s to tap Allow
                }
            }
            else if (resp.command == A_AUTH && resp.arg0 == ADB_AUTH_SIGNATURE) {
                if (!pubkey_sent) {
                    Serial.println("[ADB] Device unauthenticated. Sending Public Key (CHECK PHONE SCREEN)...");
                    sendPacket(A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, 
                               (const uint8_t*)ADB_PUBLIC_KEY, strlen(ADB_PUBLIC_KEY) + 1);
                    pubkey_sent = true;
                    startMs = millis();
                }
            }
            else if (resp.command == A_CNXN) {
                Serial.println("\n[ADB] Handshake SUCCESSFUL! Device connected!");
                if (resp.data_length > 0) {
                    char bannerBuf[resp.data_length + 1];
                    rawRead((uint8_t*)bannerBuf, resp.data_length, 2000);
                    bannerBuf[resp.data_length] = 0;
                    Serial.printf("[ADB] Device: %s\n", bannerBuf);

                    String bModel, bCodename, bName;
                    parseAdbBanner(String(bannerBuf), bModel, bCodename, bName);
                    for (size_t i = 0; i < lastDiscoveredDevices.size(); i++) {
                        if (lastDiscoveredDevices[i].ip == currentPhoneIP) {
                            lastDiscoveredDevices[i].model = bModel;
                            lastDiscoveredDevices[i].codename = bCodename;
                            lastDiscoveredDevices[i].name = bName;
                            lastDiscoveredDevices[i].authorized = true;
                            lastDiscoveredDevices[i].displayName = formatDeviceDisplayName(bModel, bCodename, lastDiscoveredDevices[i].marketname, lastDiscoveredDevices[i].brand);
                            break;
                        }
                    }
                }
                adbAuthenticated = true;
                return true;
            }
        }
        delay(10);
    }

    Serial.println("[ADB] Handshake timed out.");
    return false;
}

void runShellCommand(const char* cmd) {
    if (!rawConnected() || !adbAuthenticated) {
        Serial.println("[ADB] Not connected. Attempting reconnection...");
        if (!performAdbHandshake()) return;
    }

    char dest[512];
    snprintf(dest, sizeof(dest), "shell:%s", cmd);
    uint32_t my_id = stream_local_id++;
    if (stream_local_id == 0) stream_local_id = 1;

    sendPacket(A_OPEN, my_id, 0, (const uint8_t*)dest, strlen(dest) + 1);

    uint32_t remote_id = 0;
    unsigned long lastActivity = millis();

    while (rawConnected() && (millis() - lastActivity < 15000)) {
        AdbMessage msg;
        int n = rawRead((uint8_t*)&msg, sizeof(AdbMessage), 200);
        if (n == sizeof(AdbMessage)) {
            lastActivity = millis();
            if (msg.command == A_OKAY) {
                remote_id = msg.arg0;
            } 
            else if (msg.command == A_WRTE) {
                if (msg.data_length > 0) {
                    char buffer[msg.data_length + 1];
                    rawRead((uint8_t*)buffer, msg.data_length, 2000);
                    buffer[msg.data_length] = '\0';
                    Serial.print(buffer);
                }
                sendPacket(A_OKAY, my_id, remote_id, NULL, 0);
            } 
            else if (msg.command == A_CLSE) {
                break;
            }
        }
        delay(2);
    }
}

// =========================================================================
// Preferences & Persistent Wi-Fi
// =========================================================================
Preferences prefs;

void saveWiFiCredentials(const String& ssid, const String& pass) {
    prefs.begin("adb_wifi", false);
    prefs.putString("ssid", ssid);
    prefs.putString("pass", pass);
    prefs.end();
}

bool loadWiFiCredentials(String& ssid, String& pass) {
    if (!prefs.begin("adb_wifi", true)) {
        return false;
    }
    ssid = prefs.getString("ssid", "");
    pass = prefs.getString("pass", "");
    prefs.end();
    return (ssid.length() > 0);
}

// Wi-Fi Interactive Connect (Non-blocking, exits on 'q' or invalid input, saves to NVS)
void interactiveWiFiConnect() {
    Serial.println("\n[WiFi] Scanning for available networks...");
    WiFi.mode(WIFI_STA);
    WiFi.setTxPower(WIFI_POWER_15dBm);
    WiFi.disconnect();
    delay(100);

    int n = WiFi.scanNetworks();
    if (n <= 0) {
        Serial.println("[WiFi] No networks found. Type 'wifi' to retry.");
        return;
    }

    Serial.printf("[WiFi] Found %d networks:\n", n);
    Serial.println("--------------------------------------------------");
    for (int i = 0; i < n; ++i) {
        Serial.printf("  [%2d] %-28s (%4d dBm)\n", i + 1, WiFi.SSID(i).c_str(), WiFi.RSSI(i));
    }
    Serial.println("--------------------------------------------------");
    Serial.printf("Select network (1 - %d, or 'q' to cancel): ", n);

    String choice = readLine(true);
    choice.trim();
    if (choice.equalsIgnoreCase("q") || choice.length() == 0 || choice == "__BOOT_SHORT__" || choice == "__BOOT_LONG__") {
        Serial.println("[WiFi] Cancelled.");
        return;
    }

    int idx = choice.toInt() - 1;
    if (idx < 0 || idx >= n) {
        Serial.println("[WiFi] Invalid selection. Cancelled.");
        return;
    }

    String targetSSID = WiFi.SSID(idx);
    String pass = "";
    if (WiFi.encryptionType(idx) != WIFI_AUTH_OPEN) {
        Serial.printf("Password for \"%s\": ", targetSSID.c_str());
        pass = readLine(true);
        pass.trim();
    }

    Serial.printf("[WiFi] Connecting to \"%s\"...", targetSSID.c_str());
    if (pass.length() > 0) {
        WiFi.begin(targetSSID.c_str(), pass.c_str());
    } else {
        WiFi.begin(targetSSID.c_str());
    }

    int timeout = 25;
    while (WiFi.status() != WL_CONNECTED && timeout > 0) {
        delay(500);
        Serial.print(".");
        timeout--;
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\n[WiFi] Connected! IP: " + WiFi.localIP().toString());
        saveWiFiCredentials(targetSSID, pass);
        Serial.println("[WiFi] Network saved to flash! Will auto-connect on next boot.");
        Serial.println("[Scan] Auto-scanning for ADB phone on network (port 5555)...");
        IPAddress found = discoverAdbDevice();
        if (found != IPAddress(0, 0, 0, 0)) {
            currentPhoneIP = found;
            disconnectAdbWireless();
            if (adbClient.connect(currentPhoneIP, ADB_PORT, 5000)) {
                performAdbHandshake();
            }
        }
    } else {
        Serial.println("\n[WiFi] Connection failed. Type 'wifi' to retry.");
    }
}

// =========================================================================
// Mode Switcher (Wireless vs Wired USB-OTG)
// =========================================================================
void switchMode(AdbTransportMode newMode) {
    currentMode = newMode;
    adbAuthenticated = false;

    if (currentMode == MODE_USB_OTG) {
        Serial.println("\n========================================");
        Serial.println("  Switched to: WIRED USB-OTG MODE       ");
        Serial.println("========================================");
        Serial.println("[USB] Please ensure your phone is connected to the Native USB port.");
        Serial.println("[USB] Detecting phone...");

        int retry = 10;
        while (!UsbAdbHost::isDeviceConnected() && retry > 0) {
            delay(200);
            retry--;
        }

        if (UsbAdbHost::isDeviceConnected()) {
            if (UsbAdbHost::claimAdbInterface()) {
                performAdbHandshake();
            }
        } else {
            Serial.println("[USB] No phone detected on USB-OTG port yet.");
            Serial.println("      (Tip: Check that 5V VBUS power is supplied to phone)");
        }
    } else {
        Serial.println("\n========================================");
        Serial.println("  Switched to: WIRELESS WI-FI MODE      ");
        Serial.println("========================================");
        if (WiFi.status() != WL_CONNECTED) {
            Serial.println("[WiFi] Wi-Fi not connected.");
            Serial.println("       Type 'wifi' to select network, or 'pair' to pair.");
        } else {
            Serial.println("[WiFi] Connected! IP: " + WiFi.localIP().toString());
        }
    }
}

// =========================================================================
// Auto-Scan for Port 5555 (Classic ADB on Android 9 & Hotspots)
// =========================================================================

void parseAdbBanner(const String& banner, String& model, String& codename, String& name) {
    int idx = 0;
    while (idx < (int)banner.length()) {
        int nextSemi = banner.indexOf(';', idx);
        String token = (nextSemi == -1) ? banner.substring(idx) : banner.substring(idx, nextSemi);
        int eq = token.indexOf('=');
        if (eq > 0) {
            String key = token.substring(0, eq);
            String val = token.substring(eq + 1);
            key.trim();
            val.trim();
            if (key == "ro.product.model") {
                model = val;
            } else if (key == "ro.product.device") {
                codename = val;
            } else if (key == "ro.product.name") {
                name = val;
            }
        }
        if (nextSemi == -1) break;
        idx = nextSemi + 1;
    }
}

String formatDeviceDisplayName(const String& model, const String& codename, const String& marketname, const String& brand) {
    String display = "";

    // 1. If we have a marketing name (e.g. "realme C63 5G")
    if (marketname.length() > 0) {
        if (model.length() > 0 && !marketname.equalsIgnoreCase(model)) {
            display = model + " - " + marketname;
        } else {
            display = marketname;
        }
        if (codename.length() > 0 && !marketname.equalsIgnoreCase(codename) && !model.equalsIgnoreCase(codename)) {
            display += " (codename: " + codename + ")";
        }
        return display;
    }

    // 2. If codename and model are both known
    if (codename.length() > 0 && model.length() > 0) {
        if (codename.equalsIgnoreCase(model)) {
            if (brand.length() > 0 && !model.startsWith(brand)) {
                display = brand + " " + model;
            } else {
                display = model;
            }
        } else {
            // e.g. "olive - Redmi 8" or "RMX3950 - RE6070L1"
            display = codename + " - " + model;
        }
        return display;
    }

    // 3. If only model is known
    if (model.length() > 0) {
        if (brand.length() > 0 && !model.startsWith(brand)) {
            return brand + " " + model;
        }
        return model;
    }

    // 4. If only codename is known
    if (codename.length() > 0) {
        return codename;
    }

    return "Android Device";
}

bool queryAdbDeviceInfo(IPAddress ip, uint16_t port, AdbDiscoveredDevice& dev) {
    dev.ip = ip;
    dev.port = port;
    dev.model = "";
    dev.codename = "";
    dev.name = "";
    dev.marketname = "";
    dev.brand = "";
    dev.displayName = "";
    dev.authorized = false;

    WiFiClient client;
    if (!client.connect(ip, port, 1000)) {
        return false;
    }

    const char* banner = "host::features=cmd\0";
    AdbMessage cnxnMsg;
    cnxnMsg.command = A_CNXN;
    cnxnMsg.arg0 = A_VERSION;
    cnxnMsg.arg1 = MAX_PAYLOAD;
    cnxnMsg.data_length = strlen(banner) + 1;
    uint32_t sum = 0;
    for (size_t i = 0; i < cnxnMsg.data_length; i++) sum += (uint8_t)banner[i];
    cnxnMsg.data_check = sum;
    cnxnMsg.magic = A_CNXN ^ 0xFFFFFFFF;

    client.write((const uint8_t*)&cnxnMsg, sizeof(cnxnMsg));
    client.write((const uint8_t*)banner, cnxnMsg.data_length);
    client.flush();

    unsigned long start = millis();
    String rawBanner = "";
    bool isAdb = false;

    while (client.connected() && (millis() - start < 2500)) {
        if (client.available() >= (int)sizeof(AdbMessage)) {
            AdbMessage resp;
            client.readBytes((char*)&resp, sizeof(AdbMessage));
            if (resp.magic != (resp.command ^ 0xFFFFFFFF)) {
                break;
            }

            isAdb = true;

            if (resp.command == A_CNXN) {
                dev.authorized = true;
                if (resp.data_length > 0 && resp.data_length < 1024) {
                    char buf[resp.data_length + 1];
                    client.readBytes(buf, resp.data_length);
                    buf[resp.data_length] = 0;
                    rawBanner = String(buf);
                }
                break;
            }
            else if (resp.command == A_AUTH && resp.arg0 == ADB_AUTH_TOKEN) {
                if (resp.data_length > 256) break;
                uint8_t token[256];
                client.readBytes((char*)token, resp.data_length);

                uint8_t sig[256];
                if (signChallengeToken(token, resp.data_length, sig)) {
                    AdbMessage authMsg;
                    authMsg.command = A_AUTH;
                    authMsg.arg0 = ADB_AUTH_SIGNATURE;
                    authMsg.arg1 = 0;
                    authMsg.data_length = 256;
                    uint32_t csum = 0;
                    for (int k = 0; k < 256; k++) csum += sig[k];
                    authMsg.data_check = csum;
                    authMsg.magic = A_AUTH ^ 0xFFFFFFFF;

                    client.write((const uint8_t*)&authMsg, sizeof(authMsg));
                    client.write(sig, 256);
                    client.flush();
                } else {
                    break;
                }
            }
            else if (resp.command == A_STLS) {
                dev.displayName = "Android Device (TLS / Wireless Debugging)";
                client.stop();
                return true;
            }
        }
        delay(10);
    }

    if (!isAdb) {
        client.stop();
        return false;
    }

    if (rawBanner.length() > 0) {
        parseAdbBanner(rawBanner, dev.model, dev.codename, dev.name);
    }

    // If authorized, try querying marketname & brand
    if (dev.authorized && client.connected()) {
        const char* shCmd = "shell:getprop ro.product.marketname; getprop ro.product.brand\0";
        uint32_t stream_id = 99;
        AdbMessage openMsg;
        openMsg.command = A_OPEN;
        openMsg.arg0 = stream_id;
        openMsg.arg1 = 0;
        openMsg.data_length = strlen(shCmd) + 1;
        uint32_t csum = 0;
        for (size_t i = 0; i < openMsg.data_length; i++) csum += (uint8_t)shCmd[i];
        openMsg.data_check = csum;
        openMsg.magic = A_OPEN ^ 0xFFFFFFFF;

        client.write((const uint8_t*)&openMsg, sizeof(openMsg));
        client.write((const uint8_t*)shCmd, openMsg.data_length);
        client.flush();

        unsigned long shStart = millis();
        String shOut = "";
        while (client.connected() && (millis() - shStart < 400)) {
            if (client.available() >= (int)sizeof(AdbMessage)) {
                AdbMessage m;
                client.readBytes((char*)&m, sizeof(AdbMessage));
                if (m.command == A_WRTE && m.data_length > 0 && m.data_length < 256) {
                    char wbuf[m.data_length + 1];
                    client.readBytes(wbuf, m.data_length);
                    wbuf[m.data_length] = 0;
                    shOut += String(wbuf);

                    AdbMessage ack;
                    ack.command = A_OKAY;
                    ack.arg0 = stream_id;
                    ack.arg1 = m.arg0;
                    ack.data_length = 0;
                    ack.data_check = 0;
                    ack.magic = A_OKAY ^ 0xFFFFFFFF;
                    client.write((const uint8_t*)&ack, sizeof(ack));
                    client.flush();
                } else if (m.command == A_CLSE) {
                    break;
                }
            }
            delay(10);
        }

        if (shOut.length() > 0) {
            shOut.replace("\r", "");
            int nl = shOut.indexOf('\n');
            if (nl >= 0) {
                dev.marketname = shOut.substring(0, nl);
                dev.marketname.trim();
                dev.brand = shOut.substring(nl + 1);
                dev.brand.trim();
            } else {
                dev.marketname = shOut;
                dev.marketname.trim();
            }
        }
    }

    client.stop();

    if (!dev.authorized) {
        dev.displayName = "Android Device (New / Tap 'Allow' on screen after selecting)";
    } else {
        dev.displayName = formatDeviceDisplayName(dev.model, dev.codename, dev.marketname, dev.brand);
    }

    return true;
}

IPAddress discoverAdbDevice() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[Scan] Wi-Fi not connected.");
        return IPAddress(0, 0, 0, 0);
    }

    disconnectAdbWireless();

    std::vector<IPAddress> candidates;
    WiFiClient probe;

    IPAddress gw = WiFi.gatewayIP();
    IPAddress local = WiFi.localIP();

    Serial.printf("\n[Scan] Checking Default Gateway (%s:5555)...\n", gw.toString().c_str());
    if (probe.connect(gw, ADB_PORT, 250)) {
        probe.stop();
        Serial.printf("[Scan] Success! ADB host found at Gateway: %s:5555\n", gw.toString().c_str());
        candidates.push_back(gw);
    } else {
        Serial.println("[Scan] Gateway 5555 closed.");
    }

    Serial.printf("[Scan] Scanning local subnet (%d.%d.%d.1 - 254:5555)...\n", local[0], local[1], local[2]);
    IPAddress target = local;

    for (int i = 1; i <= 254; i++) {
        if (i == local[3]) continue; // Skip self
        if (!candidates.empty() && candidates[0] == gw && i == gw[3]) continue; // Skip gateway if already found

        target[3] = i;
        if ((i % 50) == 0 || i == 1) {
            Serial.printf("[Scan] Probing up to %s:5555... (%d found)\n", target.toString().c_str(), (int)candidates.size());
        }

        if (probe.connect(target, ADB_PORT, 50)) {
            probe.stop();
            Serial.printf("[Scan] >> Found open ADB port on: %s:5555!\n", target.toString().c_str());
            candidates.push_back(target);
        }
    }

    if (candidates.empty()) {
        Serial.println("\n[Scan] No ADB device automatically responded on port 5555.");
        Serial.println("[Scan] You can manually connect using: connect <phone-ip>");
        return IPAddress(0, 0, 0, 0);
    }

    lastDiscoveredDevices.clear();
    Serial.printf("\n[Scan] Querying device info for %d candidate(s)...\n", (int)candidates.size());

    for (size_t i = 0; i < candidates.size(); i++) {
        AdbDiscoveredDevice dev;
        if (queryAdbDeviceInfo(candidates[i], ADB_PORT, dev)) {
            lastDiscoveredDevices.push_back(dev);
        } else {
            dev.ip = candidates[i];
            dev.port = ADB_PORT;
            dev.displayName = "Android Device (Port 5555)";
            lastDiscoveredDevices.push_back(dev);
        }
        delay(40);
    }

    if (lastDiscoveredDevices.size() == 1) {
        Serial.printf("[Scan] Found 1 device: %s:5555 - %s\n", 
                      lastDiscoveredDevices[0].ip.toString().c_str(), 
                      lastDiscoveredDevices[0].displayName.c_str());
        Serial.println("[Scan] Auto-connecting...");
        return lastDiscoveredDevices[0].ip;
    }

    Serial.println("\n==================================================");
    Serial.printf("  Multiple ADB Devices Found (%d devices)\n", (int)lastDiscoveredDevices.size());
    Serial.println("==================================================");
    for (size_t i = 0; i < lastDiscoveredDevices.size(); i++) {
        Serial.printf("  [%d] %-15s:5555  -  %s\n", 
                      (int)(i + 1), 
                      lastDiscoveredDevices[i].ip.toString().c_str(), 
                      lastDiscoveredDevices[i].displayName.c_str());
    }
    Serial.println("--------------------------------------------------");
    Serial.printf("Select device (1 - %d, or 'r' to rescan) [default 1 in 15s]: ", (int)lastDiscoveredDevices.size());

    String choice = readLine(true, 15000);
    choice.trim();

    if (choice == "__TIMEOUT__" || choice.length() == 0) {
        Serial.println("\n[Scan] No selection received, auto-connecting to [1]...");
        return lastDiscoveredDevices[0].ip;
    } else if (choice.equalsIgnoreCase("r")) {
        return discoverAdbDevice();
    } else {
        int sel = choice.toInt() - 1;
        if (sel >= 0 && sel < (int)lastDiscoveredDevices.size()) {
            return lastDiscoveredDevices[sel].ip;
        } else {
            Serial.println("[Scan] Invalid selection, defaulting to [1]...");
            return lastDiscoveredDevices[0].ip;
        }
    }
}

// =========================================================================
// ADB Wireless Pairing & Auto-Connect Workflow (Android 11+)
// =========================================================================
void runPairingWorkflow() {
    Serial.println("\n========================================");
    Serial.println("  ADB WIRELESS PAIRING (Android 11+)    ");
    Serial.println("========================================");
    Serial.println("Instructions:");
    Serial.println("1. On phone, open Settings -> Developer options -> Wireless debugging");
    Serial.println("2. Tap 'Pair device with pairing code'");
    Serial.println("========================================\n");

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[Pair] Wi-Fi must be connected to the same network as your phone.");
        interactiveWiFiConnect();
        if (WiFi.status() != WL_CONNECTED) {
            Serial.println("[Pair] Wi-Fi connection required for pairing. Aborting.");
            return;
        }
    }

    IPAddress targetIp;
    uint16_t pairingPort = 0;

    Serial.println("[Pair] Discovering pairing service on network (mDNS)...");
    if (AdbPairing::discoverPairing(targetIp, pairingPort, 5000)) {
        Serial.printf("[Pair] Auto-discovered phone: %s:%d\n", targetIp.toString().c_str(), pairingPort);
    } else {
        Serial.println("[Pair] mDNS discovery did not find pairing service.");
        Serial.printf("Enter phone IP [%s]: ", currentPhoneIP.toString().c_str());
        String ipStr = readLine(true);
        ipStr.trim();
        if (ipStr.length() > 0) {
            targetIp.fromString(ipStr);
        } else {
            targetIp = currentPhoneIP;
        }

        Serial.print("Enter pairing port (from 'Pair device' popup, e.g. 38473): ");
        String portStr = readLine(true);
        portStr.trim();
        pairingPort = portStr.toInt();
    }

    if (pairingPort == 0 || targetIp == IPAddress(0, 0, 0, 0)) {
        Serial.println("[Pair] Invalid IP or Port. Aborting.");
        return;
    }

    Serial.print("Enter 6-digit Wi-Fi pairing code: ");
    String pin = readLine(true);
    pin.trim();

    if (pin.length() == 0) {
        Serial.println("[Pair] Pairing aborted.");
        return;
    }

    bool paired = AdbPairing::pair(targetIp, pairingPort, pin, ADB_PUBLIC_KEY, ADB_CERT_PEM, ADB_PRIVATE_KEY_PEM);
    if (!paired) {
        Serial.println("\n[Pair] Pairing FAILED! Please verify:");
        Serial.println("  - The pairing dialog was kept open on the phone during pairing");
        Serial.println("  - The 6-digit PIN was typed correctly");
        return;
    }

    currentPhoneIP = targetIp;
    delay(100);
    Serial.println("\n[Pair] Searching for Wireless Debugging connect port...");
    uint16_t connectPort = 0;

    if (AdbPairing::discoverConnect(targetIp, connectPort, 5000)) {
        Serial.printf("[Connect] Auto-discovered connect port: %d\n", connectPort);
    } else {
        Serial.println("[Connect] Querying open ADB connect ports on device...");
        connectPort = AdbPairing::scanOpenPort(targetIp, 30000, 50000);
        if (connectPort == 0) {
            WiFiClient testClient;
            if (testClient.connect(targetIp, 5555, 1000)) {
                testClient.stop();
                connectPort = 5555;
            }
        }
    }

    if (connectPort > 0) {
        Serial.printf("\n[Connect] Automatically connecting to %s:%d...\n", targetIp.toString().c_str(), connectPort);
        disconnectAdbWireless();
        delay(200);
        if (adbClient.connect(targetIp, connectPort, 5000)) {
            performAdbHandshake();
        } else {
            Serial.println("[Connect] Failed to connect to port.");
        }
    } else {
        Serial.println("[Connect] Could not automatically locate the connect port.");
        Serial.print("Check your phone's 'IP address & Port' under Wireless Debugging and enter port: ");
        String cpStr = readLine(true);
        cpStr.trim();
        uint16_t manualConnectPort = cpStr.toInt();
        if (manualConnectPort > 0) {
            disconnectAdbWireless();
            delay(150);
            if (adbClient.connect(targetIp, manualConnectPort, 5000)) {
                performAdbHandshake();
            }
        }
    }
}

void printHelp() {
    Serial.println("\nCommands:");
    Serial.println("  scan                 - Scan subnet for ADB devices and select device");
    Serial.println("  devices              - List discovered ADB devices from previous scan");
    Serial.println("  connect              - Reconnect to phone or auto-discover on 5555");
    Serial.println("  connect <#|ip[:port]>- Connect to device # (e.g. connect 2) or IP");
    Serial.println("  pair                 - Start Android 11+ wireless pairing (PIN code)");
    Serial.println("  wifi                 - Connect to Wi-Fi or show status");
    Serial.println("  wifi rescan          - Scan and connect to a different Wi-Fi");
    Serial.println("  mode / usb / wifi    - Switch transport mode (USB-OTG vs Wi-Fi)");
    Serial.println("  help                 - Show this help menu");
    Serial.println("  <adb command>        - Run ADB shell command (e.g. getprop, pm list packages)");
    Serial.println("\nHardware Buttons:");
    Serial.println("  [BOOT] Short Click   - Toggle Wi-Fi / USB mode");
    Serial.println("  [BOOT] Long Hold     - Start wireless pairing");
}

// =========================================================================
// Setup & Interactive Loop
// =========================================================================
void setup() {
    // Disable brownout detector to prevent resets caused by voltage dips during Wi-Fi bursts & TLS handshakes
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
    esp_brownout_disable();

    Serial.begin(115200);
    pinMode(BOOT_PIN, INPUT_PULLUP);
    delay(1500);

    esp_err_t nvs_err = nvs_flash_init();
    if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES || nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    Serial.println("\n========================================");
    Serial.println("  ESP32-S3 Dual-Mode ADB Host           ");
    Serial.println("  (Wireless Wi-Fi + Wired USB-OTG)      ");
    Serial.println("========================================");
    printHelp();

    wolfSSL_Init();
    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_parse_key(
        &pk_ctx,
        (const unsigned char*)ADB_PRIVATE_KEY_PEM,
        strlen(ADB_PRIVATE_KEY_PEM) + 1,
        NULL,
        0,
        esp_rng_wrapper,
        NULL
    );

    // Initialize USB Host hardware stack
    UsbAdbHost::init();

    // Try auto-connecting to saved Wi-Fi
    String savedSSID, savedPass;
    if (loadWiFiCredentials(savedSSID, savedPass)) {
        Serial.printf("\n[WiFi] Auto-connecting to saved network \"%s\"...\n", savedSSID.c_str());
        WiFi.mode(WIFI_STA);
        WiFi.setTxPower(WIFI_POWER_15dBm);
        WiFi.begin(savedSSID.c_str(), savedPass.c_str());
        int timeout = 14;
        while (WiFi.status() != WL_CONNECTED && timeout > 0) {
            delay(500);
            Serial.print(".");
            timeout--;
        }
        if (WiFi.status() == WL_CONNECTED) {
            Serial.println("\n[WiFi] Connected! IP: " + WiFi.localIP().toString());
            Serial.println("[Scan] Auto-scanning for ADB phone on network (port 5555)...");
            IPAddress found = discoverAdbDevice();
            if (found != IPAddress(0, 0, 0, 0)) {
                currentPhoneIP = found;
                disconnectAdbWireless();
                if (adbClient.connect(currentPhoneIP, ADB_PORT, 5000)) {
                    performAdbHandshake();
                }
            }
        } else {
            Serial.println("\n[WiFi] Failed to connect to saved network. Type 'wifi' to scan.");
        }
    } else {
        Serial.println("\n[WiFi] No saved Wi-Fi network.");
        Serial.println("       Type 'wifi' to connect to your phone's hotspot or Wi-Fi.");
    }
}

void loop() {
    Serial.printf("\nadb(%s)> ", (currentMode == MODE_WIRELESS) ? "wifi" : "usb");
    String cmd = readLine(true);
    cmd.trim();

    if (cmd == "__BOOT_LONG__" || cmd.equalsIgnoreCase("pair")) {
        runPairingWorkflow();
    } else if (cmd.equalsIgnoreCase("scan") || cmd.equalsIgnoreCase("scan 5555")) {
        Serial.println("[Scan] Searching for ADB phone on port 5555...");
        IPAddress found = discoverAdbDevice();
        if (found != IPAddress(0, 0, 0, 0)) {
            currentPhoneIP = found;
            disconnectAdbWireless();
            if (adbClient.connect(currentPhoneIP, ADB_PORT, 5000)) {
                performAdbHandshake();
            }
        }
    } else if (cmd.equalsIgnoreCase("devices") || cmd.equalsIgnoreCase("list")) {
        if (lastDiscoveredDevices.empty()) {
            Serial.println("[Devices] No devices in list. Type 'scan' to scan network.");
        } else {
            Serial.println("\n==================================================");
            Serial.println("  Discovered ADB Devices");
            Serial.println("==================================================");
            for (size_t i = 0; i < lastDiscoveredDevices.size(); i++) {
                bool isCurrent = (currentPhoneIP == lastDiscoveredDevices[i].ip && rawConnected());
                Serial.printf("  [%d] %-15s:5555  -  %s %s\n",
                              (int)(i + 1),
                              lastDiscoveredDevices[i].ip.toString().c_str(),
                              lastDiscoveredDevices[i].displayName.c_str(),
                              isCurrent ? "[CONNECTED]" : "");
            }
            Serial.println("--------------------------------------------------");
            Serial.println("Type 'connect <#>' (e.g. 'connect 1' or 'connect 2') to switch.");
        }
    } else if (cmd == "__BOOT_SHORT__" || cmd.equalsIgnoreCase("mode")) {
        switchMode(currentMode == MODE_WIRELESS ? MODE_USB_OTG : MODE_WIRELESS);
    } else if (cmd.equalsIgnoreCase("usb") || cmd.equalsIgnoreCase("mode usb")) {
        switchMode(MODE_USB_OTG);
    } else if (cmd.equalsIgnoreCase("wifi") || cmd.equalsIgnoreCase("mode wifi")) {
        if (currentMode != MODE_WIRELESS) {
            switchMode(MODE_WIRELESS);
        }
        if (WiFi.status() != WL_CONNECTED) {
            interactiveWiFiConnect();
        } else {
            Serial.println("[WiFi] Already connected to: " + WiFi.SSID() + " (" + WiFi.localIP().toString() + ")");
            Serial.println("Type 'wifi rescan' to connect to a different network, or 'scan' to find phone.");
        }
    } else if (cmd.equalsIgnoreCase("wifi rescan") || cmd.equalsIgnoreCase("wifi scan")) {
        interactiveWiFiConnect();
    } else if (cmd.equalsIgnoreCase("help") || cmd.equalsIgnoreCase("?")) {
        printHelp();
    } else if (cmd.equalsIgnoreCase("connect") || cmd.startsWith("connect ") || cmd.startsWith("adb connect ")) {
        String ipPortStr = cmd;
        if (ipPortStr.startsWith("adb connect ")) ipPortStr = ipPortStr.substring(12);
        else if (ipPortStr.startsWith("connect ")) ipPortStr = ipPortStr.substring(8);
        ipPortStr.trim();

        int devNum = ipPortStr.toInt();
        if (devNum >= 1 && devNum <= (int)lastDiscoveredDevices.size() && ipPortStr.indexOf('.') == -1) {
            currentPhoneIP = lastDiscoveredDevices[devNum - 1].ip;
            Serial.printf("[Connect] Switching to device [%d]: %s:5555 (%s)...\n",
                          devNum,
                          currentPhoneIP.toString().c_str(),
                          lastDiscoveredDevices[devNum - 1].displayName.c_str());
            disconnectAdbWireless();
            if (adbClient.connect(currentPhoneIP, ADB_PORT, 5000)) {
                performAdbHandshake();
            } else {
                Serial.println("[Connect] Failed to connect to device.");
            }
        }
        else if (ipPortStr.equalsIgnoreCase("connect") || ipPortStr.length() == 0) {
            if (currentPhoneIP != IPAddress(0, 0, 0, 0)) {
                Serial.printf("[Connect] Reconnecting to %s:%d...\n", currentPhoneIP.toString().c_str(), ADB_PORT);
                disconnectAdbWireless();
                delay(100);
                if (adbClient.connect(currentPhoneIP, ADB_PORT, 2500)) {
                    performAdbHandshake();
                } else {
                    Serial.println("[Connect] Port 5555 not open. Searching for Android Wireless Debugging service (mDNS)...");
                    uint16_t tlsPort = 0;
                    if (AdbPairing::discoverConnect(currentPhoneIP, tlsPort, 3000)) {
                        Serial.printf("[Connect] Connecting to auto-discovered port %d...\n", tlsPort);
                        disconnectAdbWireless();
                        delay(150);
                        if (adbClient.connect(currentPhoneIP, tlsPort, 5000)) {
                            performAdbHandshake();
                        }
                    } else {
                        Serial.println("[Connect] Failed to connect. Auto-scanning subnet for phone...");
                        IPAddress found = discoverAdbDevice();
                        if (found != IPAddress(0, 0, 0, 0)) {
                            currentPhoneIP = found;
                            disconnectAdbWireless();
                            delay(100);
                            if (adbClient.connect(currentPhoneIP, ADB_PORT, 5000)) {
                                performAdbHandshake();
                            }
                        }
                    }
                }
            } else {
                Serial.println("[Connect] No previous IP known. Searching for Android Wireless Debugging service (mDNS)...");
                IPAddress anyIp(0, 0, 0, 0);
                uint16_t tlsPort = 0;
                if (AdbPairing::discoverConnect(anyIp, tlsPort, 3000)) {
                    currentPhoneIP = anyIp;
                    Serial.printf("[Connect] Connecting to %s:%d...\n", currentPhoneIP.toString().c_str(), tlsPort);
                    disconnectAdbWireless();
                    delay(150);
                    if (adbClient.connect(currentPhoneIP, tlsPort, 5000)) {
                        performAdbHandshake();
                    }
                } else {
                    Serial.println("[Connect] Auto-scanning subnet for phone on port 5555...");
                    IPAddress found = discoverAdbDevice();
                    if (found != IPAddress(0, 0, 0, 0)) {
                        currentPhoneIP = found;
                        disconnectAdbWireless();
                        delay(100);
                        if (adbClient.connect(currentPhoneIP, ADB_PORT, 5000)) {
                            performAdbHandshake();
                        }
                    }
                }
            }
        } else {
            int colonIdx = ipPortStr.indexOf(':');
            uint16_t port = ADB_PORT;
            String ipStr = ipPortStr;
            if (colonIdx > 0) {
                ipStr = ipPortStr.substring(0, colonIdx);
                port = ipPortStr.substring(colonIdx + 1).toInt();
            }
            IPAddress targetIp;
            if (targetIp.fromString(ipStr)) {
                currentPhoneIP = targetIp;
                Serial.printf("[Connect] Connecting to %s:%d...\n", currentPhoneIP.toString().c_str(), port);
                disconnectAdbWireless();
                delay(150);
                if (adbClient.connect(currentPhoneIP, port, 5000)) {
                    performAdbHandshake();
                } else {
                    Serial.println("[Connect] Connection failed.");
                }
            } else {
                Serial.println("[Connect] Invalid IP address format.");
            }
        }
    } else if (cmd.length() > 0) {
        runShellCommand(cmd.c_str());
    }
}
