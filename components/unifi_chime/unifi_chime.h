// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#pragma once

#include "esphome/core/component.h"
#include "esphome/core/automation.h"
#include "esphome/core/helpers.h"
#include "esphome/components/binary_sensor/binary_sensor.h"

#include "binme.h"
#include "ucp4.h"
#include "discovery.h"
#include "adoption.h"

namespace esphome {
namespace unifi_chime {

/// Top-level ESPHome component that wires together all UniFi Chime subsystems.
class UnifiChimeComponent : public Component {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  void add_on_ring_callback(std::function<void(uint8_t, uint8_t)> &&callback) {
    ring_callbacks_.add(std::move(callback));
  }
  void add_on_buzzer_callback(std::function<void()> &&callback) {
    buzzer_callbacks_.add(std::move(callback));
  }

  void set_adopted_binary_sensor(binary_sensor::BinarySensor *sens) { adopted_sensor_ = sens; }
  void set_connected_binary_sensor(binary_sensor::BinarySensor *sens) { connected_sensor_ = sens; }

  bool is_adopted() const;
  bool is_connected() const;

 protected:
  AdoptionState adoption_;
  Discovery discovery_;
  UCP4Client ucp4_;
  CallbackManager<void(uint8_t, uint8_t)> ring_callbacks_;
  CallbackManager<void()> buzzer_callbacks_;
  binary_sensor::BinarySensor *adopted_sensor_{nullptr};
  binary_sensor::BinarySensor *connected_sensor_{nullptr};
  bool last_adopted_{false};
  bool last_connected_{false};

  /// Populate identity fields from MAC address.
  void init_identity_();

  /// Handle incoming UCP4 commands from the controller.
  std::string handle_command_(const std::string &action, const std::string &body);
};

/// Trigger that fires when the controller sends a playSpeaker command.
/// Template arguments: track_no (uint8_t), volume (uint8_t).
class ChimeRingTrigger : public Trigger<uint8_t, uint8_t> {
 public:
  explicit ChimeRingTrigger(UnifiChimeComponent *parent) {
    parent->add_on_ring_callback([this](uint8_t track_no, uint8_t volume) {
      this->trigger(track_no, volume);
    });
  }
};

/// Trigger that fires when the controller sends a playBuzzer command.
class ChimeBuzzerTrigger : public Trigger<> {
 public:
  explicit ChimeBuzzerTrigger(UnifiChimeComponent *parent) {
    parent->add_on_buzzer_callback([this]() { this->trigger(); });
  }
};

}  // namespace unifi_chime
}  // namespace esphome
