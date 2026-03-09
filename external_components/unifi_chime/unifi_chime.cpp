// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#include "unifi_chime.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"

#include "cJSON.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_system.h"

namespace esphome {
namespace unifi_chime {

static const char *const TAG = "unifi_chime";

void UnifiChimeComponent::setup() {
  ESP_LOGI(TAG, "Initializing UniFi Chime component");

  init_identity_();

  // Check NVS for saved adoption — skip discovery if already adopted
  if (adoption_.load_from_nvs()) {
    ESP_LOGI(TAG, "Restored adoption from NVS, will connect when WiFi is ready");
    adoption_.set_state(AdoptionPhase::ADOPTED);
    adoption_.start_https_server();
    return;
  }

  // No saved adoption — start discovery
  discovery_.start(adoption_.identity());
  adoption_.start_https_server();

  ESP_LOGI(TAG, "Discovery and HTTPS server started, waiting for adoption");
}

void UnifiChimeComponent::loop() {
  adoption_.loop();

  // Publish binary sensor state changes
  bool adopted = is_adopted();
  bool connected = is_connected();
  if (adopted_sensor_ && adopted != last_adopted_) {
    adopted_sensor_->publish_state(adopted);
    last_adopted_ = adopted;
  }
  if (connected_sensor_ && connected != last_connected_) {
    connected_sensor_->publish_state(connected);
    last_connected_ = connected;
  }

  switch (adoption_.state()) {
    case AdoptionPhase::WAITING_FOR_ADOPT:
      // Discovery is running, HTTPS server is listening
      break;

    case AdoptionPhase::ADOPTED: {
      // Check current WiFi state
      esp_netif_ip_info_t ip_info;
      esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
      bool has_ip = netif &&
                    esp_netif_get_ip_info(netif, &ip_info) == ESP_OK &&
                    ip_info.ip.addr != 0;

      if (!has_ip) {
        // WiFi is down — stop UCP4 if running
        if (ucp4_.is_started()) {
          ESP_LOGW(TAG, "WiFi lost, stopping UCP4");
          ucp4_.stop();
        }
        break;  // Wait for WiFi to come back
      }

      // WiFi is up — check if IP changed
      char ip_str[16];
      snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));

      if (ucp4_.is_started()) {
        // Running — check for IP change
        if (adoption_.config().ip_address != ip_str) {
          ESP_LOGI(TAG, "IP changed to %s, reconnecting", ip_str);
          ucp4_.stop();
          adoption_.config().ip_address = ip_str;
          // Will restart on next loop iteration
        } else {
          ucp4_.loop();
        }
        break;
      }

      // Not started — connect
      adoption_.config().ip_address = ip_str;
      ESP_LOGI(TAG, "Connecting to controller (ip=%s)", ip_str);
      discovery_.stop();
      ucp4_.set_command_handler(
          [this](const std::string &action, const std::string &body) {
            return handle_command_(action, body);
          });
      ucp4_.start(adoption_.config());
      ucp4_.loop();
      break;
    }

    default:
      break;
  }
}

void UnifiChimeComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "UniFi Chime:");
  ESP_LOGCONFIG(TAG, "  x-ident: %s", adoption_.identity().ident.c_str());
  ESP_LOGCONFIG(TAG, "  x-sysid: %s", adoption_.identity().sysid_hex.c_str());
  ESP_LOGCONFIG(TAG, "  State: %d", static_cast<int>(adoption_.state()));
}

void UnifiChimeComponent::init_identity_() {
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_STA, mac);

  DeviceIdentity &id = adoption_.identity();
  id.mac.assign(mac, mac + 6);
  id.name = "UP Chime";
  id.short_type = "up-chime";
  id.ble_type = "Chime";
  id.sysid = 0xF9EE;

  // x-sysid: "F9EE"
  char sysid_buf[8];
  snprintf(sysid_buf, sizeof(sysid_buf), "%04X", id.sysid);
  id.sysid_hex = sysid_buf;

  // MAC string for x-ident: "AABBCCDDEEFF"
  char mac_buf[16];
  snprintf(mac_buf, sizeof(mac_buf), "%02X%02X%02X%02X%02X%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  id.mac_string = mac_buf;

  // BLE name: "Chime-AABBCCDDEEFF"
  char ident_buf[32];
  snprintf(ident_buf, sizeof(ident_buf), "Chime-%s", mac_buf);
  id.ident = ident_buf;

  // anonymous_id: "UP Chime-AABBCC" (last 3 MAC bytes)
  char anon_buf[32];
  snprintf(anon_buf, sizeof(anon_buf), "%s-%02X%02X%02X", id.name.c_str(), mac[3], mac[4], mac[5]);
  id.anonymous_id = anon_buf;

  // x-device-id: UUID format from MAC (padded)
  char uuid_buf[48];
  snprintf(uuid_buf, sizeof(uuid_buf),
           "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  id.device_id = uuid_buf;
  // x-guid: same format, could be different value — use same for now
  id.guid = uuid_buf;

  id.fw_version = "UP.esp32.v1.7.20.0.402a5ff.240910.0648";
  id.short_version = "v1.7.20";

  ESP_LOGI(TAG, "Identity: %s (sysid %s)", id.ident.c_str(), id.sysid_hex.c_str());
}

std::string UnifiChimeComponent::handle_command_(const std::string &action,
                                                   const std::string &body) {
  const auto &id = adoption_.identity();
  auto &config = adoption_.config();

  if (action == "getInfo") {
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "name", id.name.c_str());
    cJSON_AddStringToObject(r, "fw_version", id.fw_version.c_str());
    cJSON_AddStringToObject(r, "version", id.short_version.c_str());

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             id.mac[0], id.mac[1], id.mac[2], id.mac[3], id.mac[4], id.mac[5]);
    cJSON_AddStringToObject(r, "mac", mac_str);
    cJSON_AddNumberToObject(r, "uptime",
                            static_cast<double>(millis() / 1000));
    cJSON_AddBoolToObject(r, "hasWifi", true);
    cJSON_AddBoolToObject(r, "hasHttpsClientOTA", true);
    cJSON_AddBoolToObject(r, "supportCustomRingtone", true);
    cJSON_AddItemToObject(r, "featureFlags", cJSON_CreateObject());

    char *s = cJSON_PrintUnformatted(r);
    std::string result(s);
    free(s);
    cJSON_Delete(r);
    return result;
  }

  if (action == "changeUserPassword") {
    cJSON *b = cJSON_Parse(body.c_str());
    if (b) {
      cJSON *new_pass = cJSON_GetObjectItem(b, "passwordNew");
      cJSON *new_user = cJSON_GetObjectItem(b, "username");
      if (new_pass && cJSON_IsString(new_pass)) {
        config.password = new_pass->valuestring;
        ESP_LOGI(TAG, "Password changed");
      }
      if (new_user && cJSON_IsString(new_user))
        config.username = new_user->valuestring;
      cJSON_Delete(b);
    }
    adoption_.save_to_nvs();
    return "\"ok\"";
  }

  if (action == "networkStatus") {
    wifi_ap_record_t ap_info;
    int8_t rssi = -99;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
      rssi = ap_info.rssi;

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             id.mac[0], id.mac[1], id.mac[2], id.mac[3], id.mac[4], id.mac[5]);

    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "rssi", rssi);
    cJSON_AddStringToObject(r, "mac", mac_str);
    cJSON_AddStringToObject(r, "ip", config.ip_address.c_str());

    // AP scan list — just report the currently connected AP
    cJSON *ap_list = cJSON_AddArrayToObject(r, "apList");
    if (rssi != -99) {
      cJSON *ap = cJSON_CreateObject();
      cJSON_AddStringToObject(ap, "essid",
                              reinterpret_cast<const char *>(ap_info.ssid));
      cJSON_AddNumberToObject(ap, "signalLevel", rssi);
      cJSON_AddNumberToObject(ap, "frequency",
                              ap_info.primary <= 14
                                  ? 2407 + ap_info.primary * 5
                                  : 5000 + ap_info.primary * 5);
      cJSON_AddNumberToObject(ap, "quality",
                              std::min(100, std::max(0, 2 * (rssi + 100))));
      cJSON_AddStringToObject(ap, "encryption", "wpa2");
      cJSON_AddStringToObject(ap, "authSuites", "psk");
      cJSON_AddItemToArray(ap_list, ap);
    }

    char *s = cJSON_PrintUnformatted(r);
    std::string result(s);
    free(s);
    cJSON_Delete(r);
    return result;
  }

  if (action == "getAudioInfo") {
    cJSON *r = cJSON_CreateObject();
    cJSON *tracks = cJSON_AddArrayToObject(r, "tracks");
    cJSON *t0 = cJSON_CreateObject();
    cJSON_AddNumberToObject(t0, "track_no", 0);
    cJSON_AddStringToObject(t0, "name", "default");
    cJSON_AddItemToArray(tracks, t0);
    cJSON_AddNumberToObject(r, "volume", 100);
    cJSON_AddBoolToObject(r, "speaker", true);

    char *s = cJSON_PrintUnformatted(r);
    std::string result(s);
    free(s);
    cJSON_Delete(r);
    return result;
  }

  if (action == "playSpeaker") {
    ESP_LOGI(TAG, "playSpeaker: %s", body.c_str());
    uint8_t track_no = 0;
    uint8_t volume = 100;
    cJSON *b = cJSON_Parse(body.c_str());
    if (b) {
      cJSON *tn = cJSON_GetObjectItem(b, "track_no");
      if (tn && cJSON_IsNumber(tn))
        track_no = static_cast<uint8_t>(tn->valueint);
      cJSON *vol = cJSON_GetObjectItem(b, "volume");
      if (vol && cJSON_IsNumber(vol))
        volume = static_cast<uint8_t>(vol->valueint);
      cJSON_Delete(b);
    }
    ring_callbacks_.call(track_no, volume);
    return "\"ok\"";
  }

  if (action == "playBuzzer") {
    ESP_LOGI(TAG, "playBuzzer: %s", body.c_str());
    buzzer_callbacks_.call();
    return "\"ok\"";
  }

  if (action == "setLEDState") {
    ESP_LOGI(TAG, "setLEDState: %s", body.c_str());
    return "\"ok\"";
  }

  if (action == "setTimezone") {
    return "\"ok\"";
  }

  if (action == "reboot") {
    ESP_LOGW(TAG, "Reboot requested by controller");
    delay(100);
    esp_restart();
    return "\"ok\"";
  }

  if (action == "updateFirmware") {
    ESP_LOGI(TAG, "OTA requested: %s", body.c_str());
    return "\"ok\"";
  }

  if (action == "factoryReset") {
    ESP_LOGW(TAG, "Factory reset requested");
    adoption_.clear_nvs();
    delay(100);
    esp_restart();
    return "\"ok\"";
  }

  ESP_LOGW(TAG, "Unhandled command: %s", action.c_str());
  return "{}";
}

bool UnifiChimeComponent::is_adopted() const {
  return adoption_.state() == AdoptionPhase::ADOPTED;
}

bool UnifiChimeComponent::is_connected() const {
  return ucp4_.is_started() && ucp4_.is_connected();
}

}  // namespace unifi_chime
}  // namespace esphome
