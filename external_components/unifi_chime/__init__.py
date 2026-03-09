# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 Qoole (https://github.com/Qoole)

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.const import CONF_ID
from esphome.components.esp32 import add_idf_component, add_idf_sdkconfig_option, include_builtin_idf_component

DEPENDENCIES = ["wifi"]
AUTO_LOAD = []
CODEOWNERS = ["@qoole"]

unifi_chime_ns = cg.esphome_ns.namespace("unifi_chime")
UnifiChimeComponent = unifi_chime_ns.class_("UnifiChimeComponent", cg.Component)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(UnifiChimeComponent),
    }
).extend(cv.COMPONENT_SCHEMA)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    # IDF components
    add_idf_component(
        name="espressif/esp_websocket_client",
        ref="^1.6.1",
    )
    include_builtin_idf_component("esp_https_server")

    # sdkconfig options required by this component
    # BLE (for discovery advertisement)
    add_idf_sdkconfig_option("CONFIG_BT_ENABLED", True)
    add_idf_sdkconfig_option("CONFIG_BT_BLUEDROID_ENABLED", True)
    add_idf_sdkconfig_option("CONFIG_BT_BLE_ENABLED", True)
    # HTTPS server
    add_idf_sdkconfig_option("CONFIG_ESP_HTTPS_SERVER_ENABLE", True)
    # TLS (ECDSA certs for WSS and HTTPS)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE", False)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_ECDSA_C", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED", True)
    # Skip server cert verification (controller cert is not signed by factory CA)
    add_idf_sdkconfig_option("CONFIG_ESP_TLS_INSECURE", True)
    add_idf_sdkconfig_option("CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY", True)
