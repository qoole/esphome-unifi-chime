// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#include "ucp4.h"
#include "adoption.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"

#include "cJSON.h"
#include "esp_wifi.h"

#include "factory_certs.h"

namespace esphome {
namespace unifi_chime {

static const char *const TAG = "ucp4";

static constexpr uint32_t STATUS_INTERVAL_MS = 30000;
static constexpr int WS_BUFFER_SIZE = 5120;
static constexpr int WS_TIMEOUT_SEC = 60;

std::string UCP4Client::build_url_() const {
  if (!config_ || config_->hosts.empty())
    return {};
  const auto &host = config_->hosts[0];
  char buf[128];
  snprintf(buf, sizeof(buf), "wss://%s:%d", host.hostname.c_str(), host.port);
  return buf;
}

void UCP4Client::start(const AdoptionConfig &config) {
  config_ = &config;
  connected_ = false;
  console_info_sent_ = false;
  request_id_counter_ = 0;

  std::string url = build_url_();
  if (url.empty()) {
    ESP_LOGE(TAG, "No hosts configured");
    return;
  }

  ESP_LOGI(TAG, "Connecting to %s", url.c_str());
  ESP_LOGI(TAG, "  client_cert_len=%u, client_key_len=%u",
           (unsigned)FACTORY_CA_PEM_LEN, (unsigned)FACTORY_KEY_PEM_LEN);

  // Build headers matching firmware format exactly
  std::string token_hdr;
  if (!config_->token.empty())
    token_hdr = "x-token: " + config_->token + "\r\n";

  char hdr_buf[640];
  snprintf(hdr_buf, sizeof(hdr_buf),
           "x-adopted: %s\r\n"
           "x-sysid: %04X\r\n"
           "x-type: %s\r\n"
           "x-ident: %s\r\n"  // MAC address, not BLE name
           "x-ip: %s\r\n"
           "x-mode: 0\r\n"
           "x-device-id: %s\r\n"
           "x-guid: %s\r\n"
           "x-version: %s\r\n"
           "%s",
           config_->adopted ? "true" : "false",
           config_->identity->sysid,
           config_->identity->name.c_str(),
           config_->identity->mac_string.c_str(),
           config_->ip_address.c_str(),
           config_->identity->device_id.c_str(),
           config_->identity->guid.c_str(),
           config_->identity->fw_version.c_str(),
           token_hdr.c_str());

  ESP_LOGI(TAG, "WSS headers:\n%s", hdr_buf);

  // Store on heap — websocket client may reference after init
  headers_ = strdup(hdr_buf);

  esp_websocket_client_config_t ws_cfg = {};
  ws_cfg.uri = url.c_str();
  ws_cfg.buffer_size = WS_BUFFER_SIZE;
  ws_cfg.network_timeout_ms = WS_TIMEOUT_SEC * 1000;
  // Client cert/key for mutual TLS (device identity)
  ws_cfg.client_cert = FACTORY_CA_PEM;
  ws_cfg.client_cert_len = FACTORY_CA_PEM_LEN;
  ws_cfg.client_key = FACTORY_KEY_PEM;
  ws_cfg.client_key_len = FACTORY_KEY_PEM_LEN;
  // Skip server cert verification (firmware does the same)
  ws_cfg.subprotocol = "ucp4";
  ws_cfg.skip_cert_common_name_check = true;
  ws_cfg.disable_auto_reconnect = false;
  ws_cfg.reconnect_timeout_ms = 5000;
  ws_cfg.headers = headers_;

  ws_handle_ = esp_websocket_client_init(&ws_cfg);
  if (!ws_handle_) {
    ESP_LOGE(TAG, "Failed to init websocket client");
    free(headers_);
    headers_ = nullptr;
    return;
  }

  esp_websocket_register_events(ws_handle_, WEBSOCKET_EVENT_ANY,
                                 ws_event_handler_, this);
  esp_websocket_client_start(ws_handle_);
  started_ = true;
}

void UCP4Client::stop() {
  if (ws_handle_) {
    esp_websocket_client_stop(ws_handle_);
    esp_websocket_client_destroy(ws_handle_);
    ws_handle_ = nullptr;
  }
  if (headers_) {
    free(headers_);
    headers_ = nullptr;
  }
  started_ = false;
  connected_ = false;
}

void UCP4Client::loop() {
  if (!started_ || !connected_)
    return;

  // Send getConsoleInfo as the first message after connecting
  if (!console_info_sent_) {
    send_get_console_info_();
    console_info_sent_ = true;
  }

  // Periodic status reports
  uint32_t now = millis();
  if (now - last_status_ms_ >= STATUS_INTERVAL_MS) {
    send_status_report_();
    last_status_ms_ = now;
  }
}

void UCP4Client::ws_event_handler_(void *arg, esp_event_base_t base,
                                    int32_t event_id, void *data) {
  auto *self = static_cast<UCP4Client *>(arg);
  self->on_ws_event_(event_id, data);
}

void UCP4Client::on_ws_event_(int32_t event_id, void *data) {
  auto *event = static_cast<esp_websocket_event_data_t *>(data);

  switch (event_id) {
    case WEBSOCKET_EVENT_CONNECTED:
      ESP_LOGI(TAG, "WebSocket connected");
      connected_ = true;
      console_info_sent_ = false;
      last_status_ms_ = 0;
      break;

    case WEBSOCKET_EVENT_DISCONNECTED:
      ESP_LOGW(TAG, "WebSocket disconnected");
      connected_ = false;
      break;

    case WEBSOCKET_EVENT_ERROR:
      ESP_LOGE(TAG, "WebSocket error");
      connected_ = false;
      break;

    case WEBSOCKET_EVENT_DATA:
      if (event->op_code == 0x02) {  // binary frame
        handle_incoming_(reinterpret_cast<const uint8_t *>(event->data_ptr),
                         event->data_len);
      }
      break;

    default:
      break;
  }
}

void UCP4Client::handle_incoming_(const uint8_t *data, size_t len) {
  BinmeMessage msg;
  if (!BinmeCodec::parse_message(data, len, msg)) {
    ESP_LOGW(TAG, "Failed to parse incoming BINME message");
    return;
  }

  ESP_LOGD(TAG, "Header: %s", msg.header.payload.c_str());
  ESP_LOGD(TAG, "Body: %s", msg.body.payload.c_str());

  cJSON *header = cJSON_Parse(msg.header.payload.c_str());
  if (!header)
    return;

  cJSON *type_item = cJSON_GetObjectItem(header, "type");
  const char *type_str = (type_item && cJSON_IsString(type_item)) ? type_item->valuestring : "";

  if (strcmp(type_str, "request") == 0) {
    // Controller command: {type:"request", action:"...", id:"uuid", timestamp:...}
    cJSON *action_item = cJSON_GetObjectItem(header, "action");
    cJSON *id_item = cJSON_GetObjectItem(header, "id");

    if (!action_item || !id_item) {
      ESP_LOGW(TAG, "Request missing action or id");
      cJSON_Delete(header);
      return;
    }

    std::string action = action_item->valuestring;
    std::string request_id = id_item->valuestring;
    cJSON_Delete(header);

    ESP_LOGI(TAG, "Command: %s (id=%s)", action.c_str(), request_id.c_str());

    std::string response_body = "{}";
    if (command_handler_) {
      response_body = command_handler_(action, msg.body.payload);
    }

    send_response_(request_id, 200, response_body);

  } else if (strcmp(type_str, "response") == 0) {
    // Response to our request (e.g. getConsoleInfo)
    cJSON *body = cJSON_Parse(msg.body.payload.c_str());
    if (body) {
      cJSON *console_id = cJSON_GetObjectItem(body, "consoleId");
      if (console_id && cJSON_IsString(console_id)) {
        console_id_ = console_id->valuestring;
        ESP_LOGI(TAG, "Console ID: %s", console_id_.c_str());
      }
      cJSON_Delete(body);
    }
    cJSON_Delete(header);

  } else {
    ESP_LOGW(TAG, "Unknown message type: %s", type_str);
    cJSON_Delete(header);
  }
}

void UCP4Client::send_get_console_info_() {
  char id_buf[16];
  snprintf(id_buf, sizeof(id_buf), "dev-%u", ++request_id_counter_);

  cJSON *header = cJSON_CreateObject();
  cJSON_AddStringToObject(header, "type", "request");
  cJSON_AddStringToObject(header, "action", "getConsoleInfo");
  cJSON_AddStringToObject(header, "id", id_buf);
  cJSON_AddNumberToObject(header, "timestamp", static_cast<double>(millis()));

  cJSON *body = cJSON_CreateObject();

  char *header_str = cJSON_PrintUnformatted(header);
  char *body_str = cJSON_PrintUnformatted(body);

  auto frame = BinmeCodec::encode_message(header_str, body_str, BINME_REQUEST);
  esp_websocket_client_send_bin(ws_handle_,
                                 reinterpret_cast<const char *>(frame.data()),
                                 frame.size(), portMAX_DELAY);

  ESP_LOGI(TAG, "Sent getConsoleInfo");

  free(header_str);
  free(body_str);
  cJSON_Delete(header);
  cJSON_Delete(body);
}

void UCP4Client::send_status_report_() {
  if (!config_ || !config_->identity)
    return;

  const auto &id = *config_->identity;

  // Build header
  char id_buf[16];
  snprintf(id_buf, sizeof(id_buf), "dev-%u", ++request_id_counter_);

  cJSON *header = cJSON_CreateObject();
  cJSON_AddStringToObject(header, "type", "request");
  cJSON_AddStringToObject(header, "action", "statusReport");
  cJSON_AddStringToObject(header, "id", id_buf);
  cJSON_AddNumberToObject(header, "timestamp", static_cast<double>(millis()));

  // Build status body with RSSI, MAC, version
  wifi_ap_record_t ap_info;
  int8_t rssi = -99;
  if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
    rssi = ap_info.rssi;

  char mac_str[18];
  snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
           id.mac[0], id.mac[1], id.mac[2], id.mac[3], id.mac[4], id.mac[5]);

  cJSON *body = cJSON_CreateObject();
  cJSON_AddNumberToObject(body, "rssi", rssi);
  cJSON_AddStringToObject(body, "mac", mac_str);
  cJSON_AddStringToObject(body, "ip", config_->ip_address.c_str());
  cJSON_AddStringToObject(body, "version", id.short_version.c_str());
  cJSON_AddNumberToObject(body, "uptime", static_cast<double>(millis() / 1000));

  char *header_str = cJSON_PrintUnformatted(header);
  char *body_str = cJSON_PrintUnformatted(body);

  auto frame = BinmeCodec::encode_message(header_str, body_str, BINME_REQUEST);
  esp_websocket_client_send_bin(ws_handle_,
                                 reinterpret_cast<const char *>(frame.data()),
                                 frame.size(), portMAX_DELAY);

  ESP_LOGD(TAG, "Sent status report (RSSI=%d)", rssi);

  free(header_str);
  free(body_str);
  cJSON_Delete(header);
  cJSON_Delete(body);
}

void UCP4Client::send_response_(const std::string &request_id, int response_code,
                                 const std::string &body_json) {
  cJSON *header = cJSON_CreateObject();
  cJSON_AddStringToObject(header, "type", "response");
  cJSON_AddStringToObject(header, "id", request_id.c_str());
  cJSON_AddNumberToObject(header, "responseCode", static_cast<double>(response_code));

  char *header_str = cJSON_PrintUnformatted(header);

  auto frame = BinmeCodec::encode_message(header_str, body_json);
  esp_websocket_client_send_bin(ws_handle_,
                                 reinterpret_cast<const char *>(frame.data()),
                                 frame.size(), portMAX_DELAY);

  ESP_LOGD(TAG, "Sent response (id=%s, code=%d)", request_id.c_str(), response_code);

  free(header_str);
  cJSON_Delete(header);
}

}  // namespace unifi_chime
}  // namespace esphome
