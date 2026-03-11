// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#include "adoption.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"
#include "esphome/core/helpers.h"

#include "cJSON.h"
#include "esp_netif.h"
#include "mbedtls/base64.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_system.h"

#include <cstring>

#include "factory_certs.h"

namespace esphome {
namespace unifi_chime {

static const char *const TAG = "adoption";

static constexpr size_t MAX_HOSTS = 128;
static constexpr const char *DEFAULT_USER = "ui";
static constexpr const char *DEFAULT_PASS = "ui";
static constexpr const char *NVS_NAMESPACE = "nvs_unifi";

// ── Auth ─────────────────────────────────────────────────────

bool AdoptionState::check_auth_(httpd_req_t *req) {
  char auth_buf[256] = {};
  if (httpd_req_get_hdr_value_str(req, "Authorization", auth_buf, sizeof(auth_buf)) != ESP_OK) {
    return false;
  }

  // Expect "Basic <base64(user:pass)>"
  const char *prefix = "Basic ";
  if (strncmp(auth_buf, prefix, 6) != 0)
    return false;

  const char *b64 = auth_buf + 6;
  size_t b64_len = strlen(b64);
  uint8_t decoded[128] = {};
  size_t decoded_len = 0;

  int ret = mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &decoded_len,
                                   reinterpret_cast<const uint8_t *>(b64), b64_len);
  if (ret != 0)
    return false;

  decoded[decoded_len] = '\0';

  // Compare against "user:pass"
  const char *expected_user = DEFAULT_USER;
  const char *expected_pass = DEFAULT_PASS;
  if (!config_.username.empty())
    expected_user = config_.username.c_str();
  if (!config_.password.empty())
    expected_pass = config_.password.c_str();

  char expected[256];
  snprintf(expected, sizeof(expected), "%s:%s", expected_user, expected_pass);

  return strcmp(reinterpret_cast<char *>(decoded), expected) == 0;
}

// ── /api/info ────────────────────────────────────────────────

std::string AdoptionState::build_info_json_() const {
  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "name", identity_.name.c_str());
  cJSON_AddStringToObject(root, "fw_version", identity_.fw_version.c_str());
  cJSON_AddStringToObject(root, "version", identity_.short_version.c_str());
  cJSON_AddBoolToObject(root, "reboot", true);
  cJSON_AddBoolToObject(root, "factoryReset", true);
  cJSON_AddNumberToObject(root, "uptime",
                          static_cast<double>((millis() - boot_time_ms_) / 1000));
  cJSON_AddBoolToObject(root, "hasWifi", true);
  cJSON_AddBoolToObject(root, "hasHttpsClientOTA", true);
  cJSON_AddBoolToObject(root, "supportCustomRingtone", true);
  cJSON_AddItemToObject(root, "featureFlags", cJSON_CreateObject());

  char *str = cJSON_PrintUnformatted(root);
  std::string result(str);
  free(str);
  cJSON_Delete(root);
  return result;
}

esp_err_t AdoptionState::handle_get_info_(httpd_req_t *req) {
  auto *self = static_cast<AdoptionState *>(req->user_ctx);
  ESP_LOGI(TAG, "GET /api/info from %s", req->uri);

  if (!self->check_auth_(req)) {
    ESP_LOGW(TAG, "GET /api/info: auth failed");
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_send(req, "Unauthorized", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
  }

  // Set identity headers
  httpd_resp_set_hdr(req, "x-type", self->identity_.name.c_str());
  httpd_resp_set_hdr(req, "x-sysid", self->identity_.sysid_hex.c_str());
  httpd_resp_set_hdr(req, "x-ident", self->identity_.mac_string.c_str());

  httpd_resp_set_type(req, "application/json");
  std::string body = self->build_info_json_();
  httpd_resp_send(req, body.c_str(), body.size());
  return ESP_OK;
}

// ── /api/adopt ───────────────────────────────────────────────

bool AdoptionState::parse_hosts_(const char *json, size_t len) {
  cJSON *root = cJSON_ParseWithLength(json, len);
  if (!root)
    return false;

  cJSON *hosts_arr = cJSON_GetObjectItem(root, "hosts");
  cJSON *token_item = cJSON_GetObjectItem(root, "token");
  cJSON *user_item = cJSON_GetObjectItem(root, "username");
  cJSON *pass_item = cJSON_GetObjectItem(root, "password");

  if (!hosts_arr || !cJSON_IsArray(hosts_arr) || !token_item) {
    cJSON_Delete(root);
    return false;
  }

  config_.hosts.clear();
  int count = cJSON_GetArraySize(hosts_arr);
  if (count > static_cast<int>(MAX_HOSTS))
    count = MAX_HOSTS;

  for (int i = 0; i < count; i++) {
    cJSON *item = cJSON_GetArrayItem(hosts_arr, i);
    if (!cJSON_IsString(item))
      continue;

    // Parse "hostname:port"
    char hostname[31] = {};
    int port = 0;
    if (sscanf(item->valuestring, "%30[^:]:%d", hostname, &port) == 2 &&
        port > 0 && port <= 65535) {
      config_.hosts.push_back({hostname, port});
    }
  }

  if (token_item && cJSON_IsString(token_item))
    config_.token = token_item->valuestring;
  if (user_item && cJSON_IsString(user_item))
    config_.username = user_item->valuestring;
  if (pass_item && cJSON_IsString(pass_item))
    config_.password = pass_item->valuestring;

  cJSON_Delete(root);
  return !config_.hosts.empty();
}

esp_err_t AdoptionState::handle_post_adopt_(httpd_req_t *req) {
  auto *self = static_cast<AdoptionState *>(req->user_ctx);
  ESP_LOGI(TAG, "POST /api/adopt");

  if (self->phase_ != AdoptionPhase::WAITING_FOR_ADOPT) {
    httpd_resp_set_status(req, "412 Precondition Failed");
    httpd_resp_send(req, "412 Precondition Failed", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
  }

  // Read request body
  int content_len = req->content_len;
  if (content_len <= 0 || content_len > 4096) {
    httpd_resp_send(req, "\"Missing fields\"", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
  }

  std::vector<char> buf(content_len + 1, 0);
  int total_received = 0;
  while (total_received < content_len) {
    int received = httpd_req_recv(req, buf.data() + total_received,
                                  content_len - total_received);
    if (received <= 0) {
      if (received == HTTPD_SOCK_ERR_TIMEOUT)
        continue;  // retry on timeout
      httpd_resp_send(req, "\"Missing fields\"", HTTPD_RESP_USE_STRLEN);
      return ESP_OK;
    }
    total_received += received;
  }

  if (!self->parse_hosts_(buf.data(), total_received)) {
    httpd_resp_send(req, "\"Missing fields\"", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
  }

  // Validate credentials from JSON body (controller sends them in body, not Basic auth)
  const char *expected_user = DEFAULT_USER;
  const char *expected_pass = DEFAULT_PASS;
  if (!self->config_.username.empty() && !self->config_.password.empty()) {
    // parse_hosts_ already extracted username/password from the body
    // For initial adoption, verify against defaults
    if (self->config_.username != expected_user || self->config_.password != expected_pass) {
      ESP_LOGW(TAG, "POST /api/adopt: invalid credentials");
      httpd_resp_set_status(req, "401 Unauthorized");
      httpd_resp_send(req, "Unauthorized", HTTPD_RESP_USE_STRLEN);
      return ESP_OK;
    }
  }

  self->config_.identity = &self->identity_;
  self->config_.adopted = false;

  // Get our IP address for UCP4 headers
  esp_netif_ip_info_t ip_info;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
    self->config_.ip_address = ip_str;
  }

  ESP_LOGI(TAG, "Adoption received: %zu hosts, token=%s",
           self->config_.hosts.size(), self->config_.token.c_str());

  self->phase_ = AdoptionPhase::ADOPTED;
  self->save_to_nvs();

  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, "{}", 2);
  return ESP_OK;
}

// ── /api/factoryResetWithoutWiFi ─────────────────────────────

esp_err_t AdoptionState::handle_factory_reset_(httpd_req_t *req) {
  auto *self = static_cast<AdoptionState *>(req->user_ctx);

  if (!self->check_auth_(req)) {
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_send(req, "Unauthorized", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
  }

  ESP_LOGW(TAG, "Factory reset requested");
  self->clear_nvs();
  httpd_resp_send(req, "\"ok\"", HTTPD_RESP_USE_STRLEN);
  esp_restart();
  return ESP_OK;
}

// ── HTTPS Server ─────────────────────────────────────────────

void AdoptionState::start_https_server() {
  boot_time_ms_ = millis();

  httpd_ssl_config_t ssl_cfg = HTTPD_SSL_CONFIG_DEFAULT();
  ssl_cfg.servercert = reinterpret_cast<const uint8_t *>(FACTORY_CA_PEM);
  ssl_cfg.servercert_len = FACTORY_CA_PEM_LEN;
  ssl_cfg.prvtkey_pem = reinterpret_cast<const uint8_t *>(FACTORY_KEY_PEM);
  ssl_cfg.prvtkey_len = FACTORY_KEY_PEM_LEN;
  ssl_cfg.httpd.max_uri_handlers = 8;
  ssl_cfg.port_secure = 8080;

  ESP_LOGI(TAG, "Starting HTTPS server on port %d...", ssl_cfg.port_secure);

  esp_err_t ret = httpd_ssl_start(&httpd_, &ssl_cfg);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start HTTPS server: %s", esp_err_to_name(ret));
    return;
  }

  // Register URI handlers
  httpd_uri_t info_uri = {
      .uri = "/api/info",
      .method = HTTP_GET,
      .handler = handle_get_info_,
      .user_ctx = this,
  };
  httpd_register_uri_handler(httpd_, &info_uri);

  httpd_uri_t adopt_uri = {
      .uri = "/api/adopt",
      .method = HTTP_POST,
      .handler = handle_post_adopt_,
      .user_ctx = this,
  };
  httpd_register_uri_handler(httpd_, &adopt_uri);

  httpd_uri_t reset_uri = {
      .uri = "/api/factoryResetWithoutWiFi",
      .method = HTTP_POST,
      .handler = handle_factory_reset_,
      .user_ctx = this,
  };
  httpd_register_uri_handler(httpd_, &reset_uri);

  ESP_LOGI(TAG, "HTTPS server started on port %d", ssl_cfg.port_secure);
}

void AdoptionState::stop_https_server() {
  if (httpd_) {
    httpd_ssl_stop(httpd_);
    httpd_ = nullptr;
  }
}

void AdoptionState::loop() {
  // Nothing to poll — HTTPS server and state transitions are event-driven
}

// ── NVS Persistence ─────────────────────────────────────────

bool AdoptionState::load_from_nvs() {
  nvs_handle_t handle;
  if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) != ESP_OK)
    return false;

  uint8_t adopted = 0;
  if (nvs_get_u8(handle, "adopted", &adopted) != ESP_OK || !adopted) {
    nvs_close(handle);
    return false;
  }

  auto read_str = [&](const char *key) -> std::string {
    size_t len = 0;
    if (nvs_get_str(handle, key, nullptr, &len) != ESP_OK || len == 0)
      return {};
    std::string val(len - 1, '\0');
    nvs_get_str(handle, key, &val[0], &len);
    return val;
  };

  config_.token = read_str("token");
  config_.username = read_str("username");
  config_.password = read_str("password");

  uint8_t host_count = 0;
  nvs_get_u8(handle, "host_count", &host_count);

  config_.hosts.clear();
  for (uint8_t i = 0; i < host_count; i++) {
    char key[12];
    snprintf(key, sizeof(key), "host_%d", i);
    std::string entry = read_str(key);
    if (entry.empty())
      continue;
    char hostname[31] = {};
    int port = 0;
    if (sscanf(entry.c_str(), "%30[^:]:%d", hostname, &port) == 2 &&
        port > 0 && port <= 65535)
      config_.hosts.push_back({hostname, port});
  }

  nvs_close(handle);

  if (config_.hosts.empty())
    return false;

  config_.identity = &identity_;
  config_.adopted = true;

  ESP_LOGI(TAG, "Loaded adoption from NVS: %zu hosts, token=%s",
           config_.hosts.size(), config_.token.c_str());
  return true;
}

void AdoptionState::save_to_nvs() {
  nvs_handle_t handle;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS for writing");
    return;
  }

  nvs_set_u8(handle, "adopted", 1);
  nvs_set_str(handle, "token", config_.token.c_str());
  nvs_set_str(handle, "username", config_.username.c_str());
  nvs_set_str(handle, "password", config_.password.c_str());

  uint8_t host_count = std::min(static_cast<size_t>(255), config_.hosts.size());
  nvs_set_u8(handle, "host_count", host_count);

  for (uint8_t i = 0; i < host_count; i++) {
    char key[12];
    snprintf(key, sizeof(key), "host_%d", i);
    char entry[64];
    snprintf(entry, sizeof(entry), "%s:%d",
             config_.hosts[i].hostname.c_str(), config_.hosts[i].port);
    nvs_set_str(handle, key, entry);
  }

  nvs_commit(handle);
  nvs_close(handle);
  ESP_LOGI(TAG, "Adoption saved to NVS");
}

void AdoptionState::clear_nvs() {
  nvs_handle_t handle;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK)
    return;
  nvs_erase_all(handle);
  nvs_commit(handle);
  nvs_close(handle);
  ESP_LOGW(TAG, "NVS adoption data cleared");
}

}  // namespace unifi_chime
}  // namespace esphome
