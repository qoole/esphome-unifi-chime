// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "esp_https_server.h"

namespace esphome {
namespace unifi_chime {

/// Device identity fields derived from MAC.
struct DeviceIdentity {
  std::vector<uint8_t> mac;   // 6-byte MAC
  std::string name;            // "UP Chime"
  std::string short_type;      // "up-chime"
  std::string ble_type;        // "Chime"
  uint16_t sysid;              // 0xF9EE
  std::string sysid_hex;       // "F9EE"
  std::string ident;           // "Chime-AABBCCDDEEFF" (BLE name)
  std::string mac_string;      // "AABBCCDDEEFF" (x-ident)
  std::string anonymous_id;    // "Chime-AABBCC"
  std::string device_id;       // UUID format
  std::string guid;            // UUID format
  std::string fw_version;      // full build string
  std::string short_version;   // "v1.7.20"
};

struct HostEntry {
  std::string hostname;
  int port;
};

/// Configuration received from /api/adopt.
struct AdoptionConfig {
  const DeviceIdentity *identity;
  std::vector<HostEntry> hosts;
  std::string token;
  std::string username;
  std::string password;
  std::string ip_address;
  bool adopted;
};

enum class AdoptionPhase {
  WAITING_FOR_ADOPT = 0,
  ADOPTED = 1,
};

/// Manages the adoption lifecycle: HTTPS server, credential storage, state transitions.
class AdoptionState {
 public:
  void start_https_server();
  void stop_https_server();
  void loop();

  /// NVS persistence — returns true if saved adoption was loaded.
  bool load_from_nvs();
  void save_to_nvs();
  void clear_nvs();

  AdoptionPhase state() const { return phase_; }
  void set_state(AdoptionPhase phase) { phase_ = phase; }

  DeviceIdentity &identity() { return identity_; }
  const DeviceIdentity &identity() const { return identity_; }

  AdoptionConfig &config() { return config_; }
  const AdoptionConfig &config() const { return config_; }

 protected:
  AdoptionPhase phase_{AdoptionPhase::WAITING_FOR_ADOPT};
  DeviceIdentity identity_;
  AdoptionConfig config_;
  httpd_handle_t httpd_{nullptr};
  uint32_t boot_time_ms_{0};

  /// HTTP handler callbacks (static trampolines).
  static esp_err_t handle_get_info_(httpd_req_t *req);
  static esp_err_t handle_post_adopt_(httpd_req_t *req);
  static esp_err_t handle_factory_reset_(httpd_req_t *req);

  /// Parse host list from JSON array.
  bool parse_hosts_(const char *json, size_t len);

  /// Check HTTP Basic auth against current credentials.
  bool check_auth_(httpd_req_t *req);

  /// Build the /api/info JSON response.
  std::string build_info_json_() const;
};

}  // namespace unifi_chime
}  // namespace esphome
