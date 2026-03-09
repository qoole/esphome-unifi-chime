// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#pragma once

#include "esphome/core/component.h"
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

 protected:
  AdoptionState adoption_;
  Discovery discovery_;
  UCP4Client ucp4_;

  /// Populate identity fields from MAC address.
  void init_identity_();

  /// Handle incoming UCP4 commands from the controller.
  std::string handle_command_(const std::string &action, const std::string &body);
};

}  // namespace unifi_chime
}  // namespace esphome
