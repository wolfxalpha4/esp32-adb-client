#pragma once

#include <Arduino.h>
#include <WiFi.h>

// ADB Pairing Protocol Constants
#define SPAKE2_MAX_MSG_SIZE 32
#define SPAKE2_MAX_KEY_SIZE 64
#define ADB_MAX_PEER_INFO_SIZE 8192

enum AdbPeerInfoType : uint8_t {
    ADB_PEER_RSA_PUB_KEY = 0,
    ADB_PEER_DEVICE_GUID = 1
};

struct __attribute__((packed)) AdbPairingHeader {
    uint8_t version;   // 1
    uint8_t type;      // 0 = SPAKE2_MSG, 1 = PEER_INFO
    uint32_t payload;  // Big-endian payload size
};

struct __attribute__((packed)) AdbPeerInfo {
    uint8_t type;
    uint8_t data[ADB_MAX_PEER_INFO_SIZE - 1];
};

class AdbPairing {
public:
    // Auto-discover the pairing service using mDNS
    static bool discoverPairing(IPAddress &outIp, uint16_t &outPort, uint32_t timeoutMs = 5000);

    // Auto-discover the wireless debugging connect port using mDNS
    static bool discoverConnect(IPAddress &ip, uint16_t &outPort, uint32_t timeoutMs = 5000);

    // Fast port scan fallback for Android's randomized ports (range 30000..50000)
    static uint16_t scanOpenPort(IPAddress ip, uint16_t startPort = 30000, uint16_t endPort = 50000);

    // Perform the pairing handshake (TLS 1.3 + SPAKE2 + AES-128-GCM)
    static bool pair(IPAddress ip, uint16_t port, const String &pin, const char* publicKey,
                     const char* certPem = nullptr, const char* privKeyPem = nullptr);
};
