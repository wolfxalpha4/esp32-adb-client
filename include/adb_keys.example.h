#pragma once

// =========================================================================
// ADB Keys & Certificate Template
// =========================================================================
// To use this project:
// 1. Copy this file to: include/adb_keys.h
// 2. Either copy keys from your computer (~/.android/adbkey and ~/.android/adbkey.pub)
//    OR generate a fresh pair:
//      openssl genrsa -out adbkey 2048
//      openssl req -new -x509 -key adbkey -out adbkey.crt -days 36500 -subj "/CN=ADB Key/"
// =========================================================================

#ifndef ADB_KEYS_DEFINED
#define ADB_KEYS_DEFINED

const char ADB_PRIVATE_KEY_PEM[] = 
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvH7fI7mDmsiWI\n"
"PASTE_YOUR_2048_BIT_RSA_PRIVATE_KEY_PEM_HERE\n"
"-----END PRIVATE KEY-----\n";

const char ADB_PUBLIC_KEY[] = 
"PASTE_YOUR_ADB_PUBLIC_KEY_STRING_HERE (from ~/.android/adbkey.pub)";

const char ADB_CERT_PEM[] = 
"-----BEGIN CERTIFICATE-----\n"
"PASTE_YOUR_SELF_SIGNED_X509_CERTIFICATE_PEM_HERE\n"
"-----END CERTIFICATE-----\n";

#endif
