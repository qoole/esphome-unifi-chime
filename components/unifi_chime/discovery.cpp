// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#include "discovery.h"
#include "adoption.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"

#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_netif.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include <cstring>

namespace esphome {
namespace unifi_chime {

static const char *const TAG = "discovery";

static constexpr uint16_t DISCOVERY_PORT = 10001;
static constexpr uint32_t UDP_POLL_MS = 100;

// ── Helper: get current WiFi IP ──────────────────────────────

static uint32_t get_wifi_ip_() {
  esp_netif_ip_info_t ip_info;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
    return ip_info.ip.addr;  // already in network byte order
  }
  return 0;
}

// ── TLV helpers ──────────────────────────────────────────────

void Discovery::tlv_write_(std::vector<uint8_t> &buf, uint8_t type,
                             const uint8_t *value, uint16_t len) {
  buf.push_back(type);
  buf.push_back(static_cast<uint8_t>(len >> 8));    // length high byte (BE)
  buf.push_back(static_cast<uint8_t>(len & 0xFF));  // length low byte
  buf.insert(buf.end(), value, value + len);
}

void Discovery::tlv_write_string_(std::vector<uint8_t> &buf, uint8_t type,
                                    const std::string &value) {
  tlv_write_(buf, type, reinterpret_cast<const uint8_t *>(value.data()),
             static_cast<uint16_t>(value.size()));
}

// ── Helper: parse UUID string to 16 binary bytes ────────────

static void uuid_string_to_bytes(const std::string &uuid_str, uint8_t out[16]) {
  int idx = 0;
  for (size_t i = 0; i < uuid_str.size() && idx < 16; i++) {
    if (uuid_str[i] == '-') continue;
    if (i + 1 >= uuid_str.size()) break;
    char hex[3] = {uuid_str[i], uuid_str[i + 1], 0};
    out[idx++] = static_cast<uint8_t>(strtol(hex, nullptr, 16));
    i++;
  }
  while (idx < 16) out[idx++] = 0;
}

// ── UDP Discovery ────────────────────────────────────────────

std::vector<uint8_t> Discovery::build_response_packet_() const {
  std::vector<uint8_t> pkt;

  // 4-byte header: version=1, cmd=0, data_length(2B BE, filled at end)
  pkt.push_back(0x01);
  pkt.push_back(0x00);
  pkt.push_back(0x00);  // length high (patched below)
  pkt.push_back(0x00);  // length low  (patched below)

  // TLV 0x0C: device type name
  tlv_write_string_(pkt, 0x0C, identity_->name);

  // TLV 0x0B: anonymous device name ("UP Chime-AABBCC")
  tlv_write_string_(pkt, 0x0B, identity_->anonymous_id);

  // TLV 0x0A: uptime (4 bytes, big-endian seconds)
  uint32_t uptime_sec = millis() / 1000;
  uint8_t uptime_bytes[4] = {
      static_cast<uint8_t>(uptime_sec >> 24),
      static_cast<uint8_t>(uptime_sec >> 16),
      static_cast<uint8_t>(uptime_sec >> 8),
      static_cast<uint8_t>(uptime_sec & 0xFF),
  };
  tlv_write_(pkt, 0x0A, uptime_bytes, 4);

  // TLV 0x04: IP address (4 bytes, network byte order)
  uint32_t ip_addr = get_wifi_ip_();
  uint8_t ip_bytes[4];
  memcpy(ip_bytes, &ip_addr, 4);
  tlv_write_(pkt, 0x04, ip_bytes, 4);

  // TLV 0x02: MAC + IP (10 bytes)
  uint8_t mac_ip[10];
  memcpy(mac_ip, identity_->mac.data(), 6);
  memcpy(mac_ip + 6, ip_bytes, 4);
  tlv_write_(pkt, 0x02, mac_ip, 10);

  // TLV 0x01: hardware MAC (6 bytes)
  tlv_write_(pkt, 0x01, identity_->mac.data(), 6);

  // TLV 0x05: MAC address (6 bytes)
  tlv_write_(pkt, 0x05, identity_->mac.data(), 6);

  // TLV 0x03: firmware version string
  tlv_write_string_(pkt, 0x03, identity_->fw_version);

  // TLV 0x10: sysid / model ID (2 bytes, little-endian per Protect parser)
  uint8_t sysid_bytes[2] = {
      static_cast<uint8_t>(identity_->sysid & 0xFF),
      static_cast<uint8_t>(identity_->sysid >> 8),
  };
  tlv_write_(pkt, 0x10, sysid_bytes, 2);

  // TLV 0x26: device ID (16 bytes, binary UUID)
  uint8_t uuid_bin[16];
  uuid_string_to_bytes(identity_->device_id, uuid_bin);
  tlv_write_(pkt, 0x26, uuid_bin, 16);

  // TLV 0x17: default/factory flag (1 byte, 0x01 = not yet adopted)
  uint8_t default_flag = 0x01;
  tlv_write_(pkt, 0x17, &default_flag, 1);

  // TLV 0x2B: GUID (16 bytes, binary UUID)
  uuid_string_to_bytes(identity_->guid, uuid_bin);
  tlv_write_(pkt, 0x2B, uuid_bin, 16);

  // TLV 0x20: UUID string (36 bytes)
  tlv_write_string_(pkt, 0x20, identity_->device_id);

  // TLV 0x2C: default credential version (matches real chime)
  uint8_t cred_ver = 0x03;
  tlv_write_(pkt, 0x2C, &cred_ver, 1);

  // Patch header bytes 2-3 with data length (big-endian)
  uint16_t data_len = static_cast<uint16_t>(pkt.size() - 4);
  pkt[2] = static_cast<uint8_t>(data_len >> 8);
  pkt[3] = static_cast<uint8_t>(data_len & 0xFF);

  return pkt;
}

void Discovery::udp_task_(void *arg) {
  auto *self = static_cast<Discovery *>(arg);
  self->udp_loop_();
  // Signal that we're done before deleting
  if (self->stop_sem_)
    xSemaphoreGive(self->stop_sem_);
  vTaskDelete(nullptr);
}

void Discovery::udp_loop_() {
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE(TAG, "Failed to create UDP socket");
    return;
  }
  udp_sock_ = sock;

  struct sockaddr_in bind_addr = {};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(DISCOVERY_PORT);
  bind_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, reinterpret_cast<struct sockaddr *>(&bind_addr),
           sizeof(bind_addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind UDP port %d", DISCOVERY_PORT);
    close(sock);
    udp_sock_ = -1;
    return;
  }

  // Non-blocking with timeout
  struct timeval tv = {.tv_sec = 0, .tv_usec = UDP_POLL_MS * 1000};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  ESP_LOGI(TAG, "UDP discovery listening on port %d", DISCOVERY_PORT);

  uint8_t rx_buf[128];
  struct sockaddr_in src_addr;
  socklen_t src_len;

  while (running_) {
    src_len = sizeof(src_addr);
    int rx = recvfrom(sock, rx_buf, sizeof(rx_buf), 0,
                      reinterpret_cast<struct sockaddr *>(&src_addr), &src_len);
    if (rx >= 4 && rx_buf[0] == 0x01 && rx_buf[1] == 0x00) {
      // Validate discovery header: version=1, cmd=0
      auto response = build_response_packet_();
      sendto(sock, response.data(), response.size(), 0,
             reinterpret_cast<struct sockaddr *>(&src_addr), src_len);
      ESP_LOGD(TAG, "Discovery response sent (%zu bytes)", response.size());
    }
  }

  close(sock);
  udp_sock_ = -1;
}

// ── BLE Advertisement ────────────────────────────────────────

std::vector<uint8_t> Discovery::build_ble_adv_data_() const {
  // BLE manufacturer-specific data (AD type 0xFF) requires:
  //   2-byte company ID (little-endian) + payload
  // Ubiquiti Bluetooth SIG company ID = 0x04C5
  //
  // Total budget for manufacturer data content (31B limit):
  //   Flags AD: 3B, Manufacturer AD header: 2B → 26B available for content
  //   Company ID: 2B + sysid TLV: 5B + IP TLV: 7B + MAC: 6B = 20B ✓
  std::vector<uint8_t> mfr_data;

  // Ubiquiti company ID (little-endian)
  mfr_data.push_back(0xC5);
  mfr_data.push_back(0x04);

  // TLV 0x0c: sysid (2 bytes, big-endian)
  uint8_t sysid_bytes[2] = {
      static_cast<uint8_t>(identity_->sysid >> 8),
      static_cast<uint8_t>(identity_->sysid & 0xFF),
  };
  tlv_write_(mfr_data, 0x0C, sysid_bytes, 2);

  // TLV 0x0a: IP address (4 bytes, network byte order)
  uint32_t ip_addr = get_wifi_ip_();
  uint8_t ip_bytes[4];
  memcpy(ip_bytes, &ip_addr, 4);
  tlv_write_(mfr_data, 0x0A, ip_bytes, 4);

  // Raw 6-byte MAC (no TLV header)
  mfr_data.insert(mfr_data.end(), identity_->mac.begin(), identity_->mac.end());

  return mfr_data;
}

void Discovery::start_ble_() {
  // Release classic BT memory to save RAM
  esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);

  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  if (esp_bt_controller_init(&bt_cfg) != ESP_OK) {
    ESP_LOGE(TAG, "BT controller init failed");
    return;
  }
  if (esp_bt_controller_enable(ESP_BT_MODE_BLE) != ESP_OK) {
    ESP_LOGE(TAG, "BT controller enable failed");
    return;
  }
  if (esp_bluedroid_init() != ESP_OK) {
    ESP_LOGE(TAG, "Bluedroid init failed");
    return;
  }
  if (esp_bluedroid_enable() != ESP_OK) {
    ESP_LOGE(TAG, "Bluedroid enable failed");
    return;
  }

  // Set BLE device name: "Chime-AABBCCDDEEFF" (full 6-byte MAC)
  esp_ble_gap_set_device_name(identity_->ident.c_str());

  // Build advertisement data — fits within 31-byte BLE limit
  // Stored as member to outlive async esp_ble_gap_config_adv_data
  ble_adv_payload_ = build_ble_adv_data_();

  // BLE advertisement is limited to 31 bytes. Budget:
  //   Flags AD: 3 bytes
  //   Manufacturer AD (0xFF): 2 + payload bytes
  // Name goes in scan response to avoid overflow.
  esp_ble_adv_data_t adv_data = {};
  adv_data.set_scan_rsp = false;
  adv_data.include_name = false;
  adv_data.include_txpower = false;
  adv_data.min_interval = 0;  // don't include connection interval AD
  adv_data.max_interval = 0;
  adv_data.manufacturer_len = ble_adv_payload_.size();
  adv_data.p_manufacturer_data = ble_adv_payload_.data();
  adv_data.service_data_len = 0;
  adv_data.p_service_data = nullptr;
  adv_data.service_uuid_len = 0;
  adv_data.p_service_uuid = nullptr;
  adv_data.flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT);

  esp_ble_gap_config_adv_data(&adv_data);

  // Scan response carries the device name
  esp_ble_adv_data_t scan_rsp = {};
  scan_rsp.set_scan_rsp = true;
  scan_rsp.include_name = true;  // "Chime-AABBCCDDEEFF" as AD type 0x09
  esp_ble_gap_config_adv_data(&scan_rsp);

  // Firmware values: adv_int_min=100 (62.5ms), adv_int_max=1000 (625ms)
  esp_ble_adv_params_t adv_params = {};
  adv_params.adv_int_min = 100;   // 62.5ms
  adv_params.adv_int_max = 1000;  // 625ms
  adv_params.adv_type = ADV_TYPE_IND;  // connectable undirected
  adv_params.own_addr_type = BLE_ADDR_TYPE_PUBLIC;
  adv_params.channel_map = ADV_CHNL_ALL;
  adv_params.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;

  esp_ble_gap_start_advertising(&adv_params);
  ESP_LOGI(TAG, "BLE advertising started as '%s'", identity_->ident.c_str());
}

void Discovery::stop_ble_() {
  esp_ble_gap_stop_advertising();
  ESP_LOGI(TAG, "BLE advertising stopped");
}

// ── Lifecycle ────────────────────────────────────────────────

void Discovery::start(const DeviceIdentity &identity) {
  identity_ = &identity;
  running_ = true;
  stop_sem_ = xSemaphoreCreateBinary();

  // Start UDP discovery task
  xTaskCreate(udp_task_, "udp_disc", 6144, this, 5, &udp_task_handle_);

  // Start BLE advertising
  start_ble_();
}

void Discovery::stop() {
  running_ = false;
  stop_ble_();

  // Wait for UDP task to exit cleanly (it polls running_ every 100ms)
  if (stop_sem_) {
    xSemaphoreTake(stop_sem_, pdMS_TO_TICKS(500));
    vSemaphoreDelete(stop_sem_);
    stop_sem_ = nullptr;
  }
  udp_task_handle_ = nullptr;
}

}  // namespace unifi_chime
}  // namespace esphome
