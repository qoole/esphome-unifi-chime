# Register this as an ESP-IDF component for the custom build steps
idf_component_register(
  SRC_DIRS "."
  INCLUDE_DIRS "."
  REQUIRES
    esp_https_server
    esp_wifi
    json         # cJSON
    bt           # Bluedroid BLE
    lwip
    mbedtls
    nvs_flash
    esp_netif
)

# Embed factory certificates as binary data
target_add_binary_data(${COMPONENT_LIB} "certs/factory_ca.pem" TEXT)
target_add_binary_data(${COMPONENT_LIB} "certs/factory_key.pem" TEXT)
