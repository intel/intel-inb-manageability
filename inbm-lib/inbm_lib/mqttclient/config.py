"""
    MQTT Configuration variables

    @copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""

# MQTT connection variables
from inbm_lib.path_prefixes import BROKER_ETC_PATH

DEFAULT_MQTT_HOST = 'localhost'
DEFAULT_MQTT_PORT = 8883
DEFAULT_MQTT_CERTS = BROKER_ETC_PATH / 'public' / 'mqtt-ca' / 'mqtt-ca.crt'
# Maximum period in seconds allowed between communications with the broker
MQTT_KEEPALIVE_INTERVAL = 60
