#pragma once

#include <Arduino.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "usb/usb_host.h"

class UsbAdbHost {
public:
    static bool init();
    static bool isDeviceConnected();
    static bool isAdbReady();
    static bool claimAdbInterface();
    static bool writeData(const uint8_t* data, size_t len);
    static int readData(uint8_t* buf, size_t max_len, uint32_t timeout_ms = 3000);
    static void closeDevice();
};
