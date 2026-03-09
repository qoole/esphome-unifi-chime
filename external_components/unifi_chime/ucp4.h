// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "binme.h"
#include "esp_websocket_client.h"

namespace esphome {
namespace unifi_chime {

struct DeviceIdentity;   // defined in adoption.h
struct AdoptionConfig;   // defined in adoption.h

/// UCP4 WebSocket client — connects to UniFi controller over WSS,
/// sends/receives BINME-framed JSON messages.
class UCP4Client {
 public:
  using CommandHandler = std::function<std::string(const std::string &action,
                                                    const std::string &body_json)>;

  bool is_started() const { return started_; }
  bool is_connected() const { return connected_; }
  void start(const AdoptionConfig &config);
  void stop();
  void loop();

  /// Register a callback for handling incoming UCP4 commands.
  void set_command_handler(CommandHandler handler) { command_handler_ = std::move(handler); }

 protected:
  bool started_{false};
  bool connected_{false};
  bool console_info_sent_{false};
  esp_websocket_client_handle_t ws_handle_{nullptr};
  char *headers_{nullptr};
  const AdoptionConfig *config_{nullptr};
  uint32_t request_id_counter_{0};
  uint32_t last_status_ms_{0};
  std::string console_id_;
  CommandHandler command_handler_;

  /// Build the WSS URL from host/port.
  std::string build_url_() const;

  /// Called on WebSocket events (static trampoline + instance method).
  static void ws_event_handler_(void *arg, esp_event_base_t base, int32_t event_id, void *data);
  void on_ws_event_(int32_t event_id, void *data);

  /// Handle an incoming BINME message from the controller.
  void handle_incoming_(const uint8_t *data, size_t len);

  /// Send getConsoleInfo request (first message after connect).
  void send_get_console_info_();

  /// Send periodic status report (RSSI, MAC, version).
  void send_status_report_();

  /// Send a UCP4 response to the controller.
  void send_response_(const std::string &request_id, int response_code,
                      const std::string &body_json);
};

}  // namespace unifi_chime
}  // namespace esphome
