// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

namespace esphome {
namespace unifi_chime {

struct DeviceIdentity;

/// Handles UDP discovery (port 10001) and BLE advertisements.
class Discovery {
 public:
  void start(const DeviceIdentity &identity);
  void stop();

 protected:
  const DeviceIdentity *identity_{nullptr};
  int udp_sock_{-1};
  std::atomic<bool> running_{false};
  TaskHandle_t udp_task_handle_{nullptr};
  SemaphoreHandle_t stop_sem_{nullptr};

  // --- UDP Discovery (port 10001) ---

  /// Build a discovery TLV response packet.
  std::vector<uint8_t> build_response_packet_() const;

  /// Write a single TLV entry: type(1B) + length(2B BE) + value(NB).
  static void tlv_write_(std::vector<uint8_t> &buf, uint8_t type,
                          const uint8_t *value, uint16_t len);
  static void tlv_write_string_(std::vector<uint8_t> &buf, uint8_t type,
                                 const std::string &value);

  /// UDP listener task (static trampoline).
  static void udp_task_(void *arg);
  void udp_loop_();

  // --- BLE Advertisement ---

  /// Start BLE advertising with UniFi discovery payload.
  void start_ble_();
  void stop_ble_();

  /// Build raw BLE advertisement data with TLV payload.
  std::vector<uint8_t> build_ble_adv_data_() const;
};

}  // namespace unifi_chime
}  // namespace esphome
