// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#pragma once

#include "esphome/core/component.h"
#include "esphome/core/automation.h"
#include "esphome/core/helpers.h"

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

  void add_on_ring_callback(std::function<void(uint8_t)> &&callback) {
    ring_callbacks_.add(std::move(callback));
  }

 protected:
  AdoptionState adoption_;
  Discovery discovery_;
  UCP4Client ucp4_;
  CallbackManager<void(uint8_t)> ring_callbacks_;

  /// Populate identity fields from MAC address.
  void init_identity_();

  /// Handle incoming UCP4 commands from the controller.
  std::string handle_command_(const std::string &action, const std::string &body);
};

/// Trigger that fires when the controller sends a playSpeaker command.
/// Template argument: track_no (uint8_t).
class ChimeRingTrigger : public Trigger<uint8_t> {
 public:
  explicit ChimeRingTrigger(UnifiChimeComponent *parent) {
    parent->add_on_ring_callback([this](uint8_t track_no) { this->trigger(track_no); });
  }
};

}  // namespace unifi_chime
}  // namespace esphome
