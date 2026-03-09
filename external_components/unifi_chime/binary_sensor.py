# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 Qoole (https://github.com/Qoole)

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import binary_sensor
from esphome.const import (
    CONF_ID,
    DEVICE_CLASS_CONNECTIVITY,
)

from . import UnifiChimeComponent, unifi_chime_ns

CONF_UNIFI_CHIME_ID = "unifi_chime_id"
CONF_ADOPTED = "adopted"
CONF_CONNECTED = "connected"

DEPENDENCIES = ["unifi_chime"]

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_UNIFI_CHIME_ID): cv.use_id(UnifiChimeComponent),
        cv.Optional(CONF_ADOPTED): binary_sensor.binary_sensor_schema(),
        cv.Optional(CONF_CONNECTED): binary_sensor.binary_sensor_schema(
            device_class=DEVICE_CLASS_CONNECTIVITY,
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_UNIFI_CHIME_ID])

    if adopted_conf := config.get(CONF_ADOPTED):
        sens = await binary_sensor.new_binary_sensor(adopted_conf)
        cg.add(parent.set_adopted_binary_sensor(sens))

    if connected_conf := config.get(CONF_CONNECTED):
        sens = await binary_sensor.new_binary_sensor(connected_conf)
        cg.add(parent.set_connected_binary_sensor(sens))
