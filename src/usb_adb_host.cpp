#include "usb_adb_host.h"
#include "esp_log.h"

static const char* TAG = "USB_ADB";

static usb_host_client_handle_t client_hdl = NULL;
static usb_device_handle_t dev_hdl = NULL;
static uint8_t dev_addr = 0;
static bool s_dev_connected = false;
static bool s_adb_claimed = false;

static uint8_t adb_intf_num = 0;
static uint8_t adb_in_ep = 0;
static uint8_t adb_out_ep = 0;

static usb_transfer_t* transfer_out = NULL;
static usb_transfer_t* transfer_in = NULL;
static SemaphoreHandle_t sem_out = NULL;
static SemaphoreHandle_t sem_in = NULL;

static void transfer_out_cb(usb_transfer_t *transfer) {
    if (sem_out) {
        xSemaphoreGive(sem_out);
    }
}

static void transfer_in_cb(usb_transfer_t *transfer) {
    if (sem_in) {
        xSemaphoreGive(sem_in);
    }
}

static void client_event_cb(const usb_host_client_event_msg_t *event_msg, void *arg) {
    switch (event_msg->event) {
        case USB_HOST_CLIENT_EVENT_NEW_DEV:
            dev_addr = event_msg->new_dev.address;
            s_dev_connected = true;
            Serial.printf("[USB] Device connected at address %d\n", dev_addr);
            break;
        case USB_HOST_CLIENT_EVENT_DEV_GONE:
            s_dev_connected = false;
            s_adb_claimed = false;
            if (dev_hdl) {
                usb_host_device_close(client_hdl, dev_hdl);
                dev_hdl = NULL;
            }
            Serial.println("[USB] Device disconnected.");
            break;
        default:
            break;
    }
}

static void usb_lib_task(void *arg) {
    while (1) {
        uint32_t event_flags;
        usb_host_lib_handle_events(portMAX_DELAY, &event_flags);
    }
}

static void usb_client_task(void *arg) {
    while (1) {
        usb_host_client_handle_events(client_hdl, portMAX_DELAY);
    }
}

bool UsbAdbHost::init() {
    if (sem_out == NULL) sem_out = xSemaphoreCreateBinary();
    if (sem_in == NULL) sem_in = xSemaphoreCreateBinary();

    usb_host_config_t host_config = {
        .skip_phy_setup = false,
        .intr_flags = ESP_INTR_FLAG_LEVEL1,
    };

    esp_err_t err = usb_host_install(&host_config);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        Serial.printf("[USB] usb_host_install failed: 0x%x\n", err);
        return false;
    }

    xTaskCreatePinnedToCore(usb_lib_task, "usb_lib", 4096, NULL, 5, NULL, 0);

    usb_host_client_config_t client_config = {
        .is_synchronous = false,
        .max_num_event_msg = 5,
        .async = {
            .client_event_callback = client_event_cb,
            .callback_arg = NULL
        }
    };

    err = usb_host_client_register(&client_config, &client_hdl);
    if (err != ESP_OK) {
        Serial.printf("[USB] client_register failed: 0x%x\n", err);
        return false;
    }

    xTaskCreatePinnedToCore(usb_client_task, "usb_client", 4096, NULL, 5, NULL, 0);

    // Allocate transfer buffers (4KB payload + 24 byte header)
    err = usb_host_transfer_alloc(4096 + 24, 0, &transfer_out);
    if (err == ESP_OK) {
        transfer_out->callback = transfer_out_cb;
        transfer_out->context = NULL;
    }

    err = usb_host_transfer_alloc(4096 + 24, 0, &transfer_in);
    if (err == ESP_OK) {
        transfer_in->callback = transfer_in_cb;
        transfer_in->context = NULL;
    }

    Serial.println("[USB] USB Host initialized. Ready for phone connection on OTG port.");
    return true;
}

bool UsbAdbHost::isDeviceConnected() {
    return s_dev_connected;
}

bool UsbAdbHost::isAdbReady() {
    return s_adb_claimed;
}

bool UsbAdbHost::claimAdbInterface() {
    if (!s_dev_connected || dev_addr == 0) return false;

    if (dev_hdl == NULL) {
        esp_err_t err = usb_host_device_open(client_hdl, dev_addr, &dev_hdl);
        if (err != ESP_OK) {
            Serial.printf("[USB] Failed to open device: 0x%x\n", err);
            return false;
        }
    }

    const usb_config_desc_t *config_desc = NULL;
    esp_err_t err = usb_host_get_active_config_descriptor(dev_hdl, &config_desc);
    if (err != ESP_OK || config_desc == NULL) {
        Serial.println("[USB] Failed to get config descriptor");
        return false;
    }

    // Parse descriptors for ADB (Class 0xFF, Subclass 0x42, Protocol 0x01)
    const uint8_t *p = (const uint8_t *)config_desc;
    const uint8_t *end = p + config_desc->wTotalLength;
    p += config_desc->bLength; // skip config header

    bool found_adb = false;
    uint8_t curr_intf = 0;

    while (p < end) {
        uint8_t len = p[0];
        uint8_t type = p[1];
        if (len == 0 || p + len > end) break;

        if (type == USB_B_DESCRIPTOR_TYPE_INTERFACE) {
            const usb_intf_desc_t *intf = (const usb_intf_desc_t *)p;
            curr_intf = intf->bInterfaceNumber;
            if (intf->bInterfaceClass == 0xFF && intf->bInterfaceSubClass == 0x42 && intf->bInterfaceProtocol == 0x01) {
                found_adb = true;
                adb_intf_num = curr_intf;
                Serial.printf("[USB] Found ADB Interface #%d!\n", adb_intf_num);
            } else {
                found_adb = false;
            }
        } else if (type == USB_B_DESCRIPTOR_TYPE_ENDPOINT && found_adb) {
            const usb_ep_desc_t *ep = (const usb_ep_desc_t *)p;
            if (ep->bEndpointAddress & 0x80) {
                adb_in_ep = ep->bEndpointAddress;
                Serial.printf("[USB] Bulk IN EP: 0x%02X\n", adb_in_ep);
            } else {
                adb_out_ep = ep->bEndpointAddress;
                Serial.printf("[USB] Bulk OUT EP: 0x%02X\n", adb_out_ep);
            }
        }
        p += len;
    }

    if (adb_in_ep != 0 && adb_out_ep != 0) {
        err = usb_host_interface_claim(client_hdl, dev_hdl, adb_intf_num, 0);
        if (err == ESP_OK) {
            s_adb_claimed = true;
            Serial.println("[USB] Claimed ADB interface successfully!");
            return true;
        } else {
            Serial.printf("[USB] Failed to claim interface: 0x%x\n", err);
        }
    } else {
        Serial.println("[USB] ADB interface/endpoints not found in descriptors.");
    }
    return false;
}

bool UsbAdbHost::writeData(const uint8_t* data, size_t len) {
    if (!dev_hdl || !s_adb_claimed || !transfer_out) return false;

    memcpy(transfer_out->data_buffer, data, len);
    transfer_out->num_bytes = len;
    transfer_out->bEndpointAddress = adb_out_ep;
    transfer_out->device_handle = dev_hdl;

    xSemaphoreTake(sem_out, 0);
    esp_err_t err = usb_host_transfer_submit(transfer_out);
    if (err != ESP_OK) {
        Serial.printf("[USB] Write submit failed: 0x%x\n", err);
        return false;
    }

    return (xSemaphoreTake(sem_out, pdMS_TO_TICKS(3000)) == pdTRUE && transfer_out->status == USB_TRANSFER_STATUS_COMPLETED);
}

int UsbAdbHost::readData(uint8_t* buf, size_t max_len, uint32_t timeout_ms) {
    if (!dev_hdl || !s_adb_claimed || !transfer_in) return -1;

    transfer_in->num_bytes = max_len;
    transfer_in->bEndpointAddress = adb_in_ep;
    transfer_in->device_handle = dev_hdl;

    xSemaphoreTake(sem_in, 0);
    esp_err_t err = usb_host_transfer_submit(transfer_in);
    if (err != ESP_OK) {
        return -1;
    }

    if (xSemaphoreTake(sem_in, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        return -1;
    }

    if (transfer_in->status == USB_TRANSFER_STATUS_COMPLETED) {
        int actual = transfer_in->actual_num_bytes;
        if (actual > 0) {
            memcpy(buf, transfer_in->data_buffer, actual);
        }
        return actual;
    }
    return -1;
}

void UsbAdbHost::closeDevice() {
    if (dev_hdl) {
        if (s_adb_claimed) {
            usb_host_interface_release(client_hdl, dev_hdl, adb_intf_num);
            s_adb_claimed = false;
        }
        usb_host_device_close(client_hdl, dev_hdl);
        dev_hdl = NULL;
    }
}
