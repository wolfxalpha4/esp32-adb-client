#include "adb_pairing.h"
#include <ESPmDNS.h>
#define WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <spake2/spake2.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>

bool AdbPairing::discoverPairing(IPAddress &outIp, uint16_t &outPort, uint32_t timeoutMs) {
    Serial.println("[mDNS] Searching for _adb-tls-pairing._tcp service...");
    if (!MDNS.begin("esp32-adb")) {
        Serial.println("[mDNS] Failed to start MDNS");
        return false;
    }

    int n = MDNS.queryService("adb-tls-pairing", "tcp");
    if (n <= 0) {
        // Try waiting a moment and query again
        delay(1000);
        n = MDNS.queryService("adb-tls-pairing", "tcp");
    }

    if (n > 0) {
        outIp = MDNS.address(0);
        outPort = MDNS.port(0);
        Serial.printf("[mDNS] Found pairing service at %s:%d\n", outIp.toString().c_str(), outPort);
        return true;
    }

    Serial.println("[mDNS] Pairing service not found via mDNS.");
    return false;
}

bool AdbPairing::discoverConnect(IPAddress &ip, uint16_t &outPort, uint32_t timeoutMs) {
    Serial.println("[mDNS] Searching for _adb-tls-connect._tcp service...");
    MDNS.begin("esp32-adb");
    int n = MDNS.queryService("adb-tls-connect", "tcp");
    if (n <= 0) {
        delay(1000);
        n = MDNS.queryService("adb-tls-connect", "tcp");
    }

    if (n > 0) {
        for (int i = 0; i < n; i++) {
            if (ip == IPAddress(0, 0, 0, 0) || MDNS.address(i) == ip || n == 1) {
                ip = MDNS.address(i);
                outPort = MDNS.port(i);
                Serial.printf("[mDNS] Found connect service at %s:%d\n", ip.toString().c_str(), outPort);
                return true;
            }
        }
    }

    Serial.println("[mDNS] Connect service not found via mDNS. Falling back to port scan...");
    return false;
}

uint16_t AdbPairing::scanOpenPort(IPAddress ip, uint16_t startPort, uint16_t endPort) {
    Serial.printf("[Scan] Scanning ports %d-%d on %s...\n", startPort, endPort, ip.toString().c_str());

    for (uint32_t p = startPort; p <= endPort; p++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(p);
        serv_addr.sin_addr.s_addr = (uint32_t)ip;

        int res = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
        if (res == 0) {
            close(sock);
            Serial.printf("[Scan] Open port discovered: %d\n", p);
            return p;
        }

        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 15000; // 15ms per port

        if (select(sock + 1, NULL, &fdset, NULL, &tv) > 0) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) {
                close(sock);
                Serial.printf("[Scan] Open port discovered: %d\n", p);
                return p;
            }
        }
        close(sock);

        if ((p % 1000) == 0) {
            Serial.printf("[Scan] Checked up to port %d...\n", p);
        }
    }

    return 0;
}

static bool readAll(WOLFSSL* ssl, uint8_t* buf, size_t len, uint32_t timeoutMs = 8000) {
    size_t received = 0;
    unsigned long start = millis();
    while (received < len && (millis() - start < timeoutMs)) {
        int n = wolfSSL_read(ssl, buf + received, len - received);
        if (n > 0) {
            received += n;
            start = millis();
        } else {
            int err = wolfSSL_get_error(ssl, n);
            if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
                return false;
            }
            delay(5);
        }
    }
    return (received == len);
}

bool AdbPairing::pair(IPAddress ip, uint16_t port, const String &pin, const char* publicKey,
                      const char* certPem, const char* privKeyPem) {
    Serial.printf("\n[Pair] Connecting to %s:%d...\n", ip.toString().c_str(), port);

    // 1. Establish raw TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        Serial.println("[Pair] Failed to create socket");
        return false;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = (uint32_t)ip;

    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        Serial.println("[Pair] TCP Connection failed");
        close(sock);
        return false;
    }

    // 2. Setup TLS 1.3 Client
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        Serial.println("[Pair] Failed to create wolfSSL CTX");
        close(sock);
        return false;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    if (certPem && privKeyPem) {
        if (wolfSSL_CTX_use_certificate_buffer(ctx, (const unsigned char*)certPem,
                                               strlen(certPem), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            Serial.println("[Pair] Failed to load certificate");
        }
        if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, (const unsigned char*)privKeyPem,
                                              strlen(privKeyPem), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            Serial.println("[Pair] Failed to load private key");
        }
    }

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) {
        Serial.println("[Pair] Failed to allocate WOLFSSL session");
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    wolfSSL_set_fd(ssl, sock);

    // wolfSSL by default frees handshake arrays upon connect; KeepArrays preserves exporterSecret for RFC 5705
    wolfSSL_KeepArrays(ssl);

    Serial.println("[Pair] Performing TLS 1.3 handshake...");
    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, 0);
        Serial.printf("[Pair] TLS handshake failed (err=%d)\n", err);
        wolfSSL_FreeArrays(ssl);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }
    Serial.println("[Pair] TLS 1.3 connected successfully!");

    // 3. Export Keying Material (RFC 5705)
    // In Android AOSP, sizeof(kExportedKeyLabel) is used which is 10 bytes including null terminator '\0'
    uint8_t exportedKey[64];
    const char label[] = "adb-label";
    if (wolfSSL_export_keying_material(ssl, exportedKey, sizeof(exportedKey),
                                       label, sizeof(label), NULL, 0, 0) != WOLFSSL_SUCCESS) {
        Serial.println("[Pair] Failed to export key material");
        wolfSSL_FreeArrays(ssl);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }
    wolfSSL_FreeArrays(ssl);

    // 4. Initialize SPAKE2 password = PIN + exportedKey
    size_t pinLen = pin.length();
    size_t pswdLen = pinLen + sizeof(exportedKey);
    uint8_t pswd[pswdLen];
    memcpy(pswd, pin.c_str(), pinLen);
    memcpy(pswd + pinLen, exportedKey, sizeof(exportedKey));

    static const uint8_t kClientName[] = "adb pair client";
    static const uint8_t kServerName[] = "adb pair server";
    struct spake2_ctx_st *spake = SPAKE2_CTX_new(spake2_role_alice,
                                                 kClientName, sizeof(kClientName),
                                                 kServerName, sizeof(kServerName));
    if (!spake) {
        Serial.println("[Pair] Failed to create SPAKE2 context");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    uint8_t ourSpakeMsg[SPAKE2_MAX_MSG_SIZE];
    size_t ourSpakeLen = 0;
    if (SPAKE2_generate_msg(spake, ourSpakeMsg, &ourSpakeLen, SPAKE2_MAX_MSG_SIZE, pswd, pswdLen) != 1) {
        Serial.println("[Pair] SPAKE2_generate_msg failed");
        SPAKE2_CTX_free(spake);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    // 5. Send our SPAKE2 message
    AdbPairingHeader outHdr;
    outHdr.version = 1;
    outHdr.type = 0; // SPAKE2_MSG
    outHdr.payload = htonl(ourSpakeLen);
    wolfSSL_write(ssl, &outHdr, sizeof(outHdr));
    wolfSSL_write(ssl, ourSpakeMsg, ourSpakeLen);

    // 6. Read peer SPAKE2 message
    AdbPairingHeader inHdr;
    if (!readAll(ssl, (uint8_t*)&inHdr, sizeof(inHdr))) {
        Serial.println("[Pair] Failed to read peer SPAKE2 header");
        SPAKE2_CTX_free(spake);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    uint32_t peerPayloadLen = ntohl(inHdr.payload);
    if (inHdr.type != 0 || peerPayloadLen != SPAKE2_MAX_MSG_SIZE) {
        Serial.printf("[Pair] Unexpected SPAKE2 packet (type=%d, len=%u)\n", inHdr.type, peerPayloadLen);
        SPAKE2_CTX_free(spake);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    uint8_t peerSpakeMsg[SPAKE2_MAX_MSG_SIZE];
    if (!readAll(ssl, peerSpakeMsg, peerPayloadLen)) {
        Serial.println("[Pair] Failed to read peer SPAKE2 payload");
        SPAKE2_CTX_free(spake);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    // 7. Compute shared key material
    uint8_t keyMaterial[SPAKE2_MAX_KEY_SIZE];
    size_t keyMaterialLen = 0;
    if (SPAKE2_process_msg(spake, keyMaterial, &keyMaterialLen, sizeof(keyMaterial), peerSpakeMsg, peerPayloadLen) != 1) {
        Serial.println("[Pair] SPAKE2_process_msg failed! (PIN incorrect or mismatch)");
        SPAKE2_CTX_free(spake);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }
    SPAKE2_CTX_free(spake);

    // 8. Derive AES-128-GCM key with HKDF-SHA256
    uint8_t aesKey[16];
    const char* hkdfInfo = "adb pairing_auth aes-128-gcm key";
    int hkdfRet = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                               NULL, 0,
                               keyMaterial, keyMaterialLen,
                               (const unsigned char*)hkdfInfo, strlen(hkdfInfo),
                               aesKey, sizeof(aesKey));
    if (hkdfRet != 0) {
        Serial.printf("[Pair] HKDF derivation failed (%d)\n", hkdfRet);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    // 9. Prepare and Encrypt our PeerInfo (ADB_PEER_RSA_PUB_KEY)
    static AdbPeerInfo ourInfo;
    memset(&ourInfo, 0, sizeof(ourInfo));
    ourInfo.type = ADB_PEER_RSA_PUB_KEY;
    strncpy((char*)ourInfo.data, publicKey, sizeof(ourInfo.data) - 1);

    static uint8_t encBuf[sizeof(ourInfo) + 16]; // payload + 16-byte tag
    uint8_t nonce[12] = {0}; // sequence 0: 64-bit int 0 in LE + 4 zero bytes
    uint8_t tag[16];

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128);

    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(ourInfo),
                              nonce, sizeof(nonce), NULL, 0,
                              (const unsigned char*)&ourInfo, encBuf,
                              16, encBuf + sizeof(ourInfo));
    mbedtls_gcm_free(&gcm);

    // Send our encrypted PeerInfo
    outHdr.version = 1;
    outHdr.type = 1; // PEER_INFO
    outHdr.payload = htonl(sizeof(ourInfo) + 16);
    wolfSSL_write(ssl, &outHdr, sizeof(outHdr));
    wolfSSL_write(ssl, encBuf, sizeof(ourInfo) + 16);

    // 10. Read peer's encrypted PeerInfo
    if (!readAll(ssl, (uint8_t*)&inHdr, sizeof(inHdr))) {
        Serial.println("[Pair] Failed to read peer info header");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    uint32_t encPeerLen = ntohl(inHdr.payload);
    if (inHdr.type != 1 || encPeerLen != (sizeof(AdbPeerInfo) + 16)) {
        Serial.printf("[Pair] Unexpected PeerInfo packet (type=%d, len=%u)\n", inHdr.type, encPeerLen);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    static uint8_t peerEncBuf[sizeof(AdbPeerInfo) + 16];
    if (!readAll(ssl, peerEncBuf, encPeerLen)) {
        Serial.println("[Pair] Failed to read peer info payload");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    // Decrypt peer info
    static AdbPeerInfo peerInfo;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128);
    int decRet = mbedtls_gcm_auth_decrypt(&gcm, sizeof(AdbPeerInfo),
                                          nonce, sizeof(nonce), NULL, 0,
                                          peerEncBuf + sizeof(AdbPeerInfo), 16,
                                          peerEncBuf, (unsigned char*)&peerInfo);
    mbedtls_gcm_free(&gcm);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(sock);

    if (decRet != 0) {
        Serial.println("[Pair] Decryption of peer info failed (invalid auth tag)!");
        return false;
    }

    if (peerInfo.type != ADB_PEER_DEVICE_GUID) {
        Serial.printf("[Pair] Unknown peer response type=%d\n", peerInfo.type);
        return false;
    }

    Serial.printf("\n========================================\n");
    Serial.printf("  PAIRING SUCCESSFUL!                   \n");
    Serial.printf("  Device GUID: %s                       \n", (char*)peerInfo.data);
    Serial.printf("========================================\n");
    return true;
}
