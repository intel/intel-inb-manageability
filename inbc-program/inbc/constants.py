""" Constants and other config variables used throughout the INBC module.

    Copyright (C) 2020-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_lib.path_prefixes import BROKER_ETC_PATH

# certs
CLIENT_CERTS = str(BROKER_ETC_PATH / 'public' / 'inbc-program' / 'inbc-program.crt')
CLIENT_KEYS = str(BROKER_ETC_PATH / 'secret' / 'inbc-program' / 'inbc-program.key')
CA_CERTS = str(BROKER_ETC_PATH / 'public' / 'mqtt-ca' / 'mqtt-ca.crt')

# MQTT constant
MQTT_HOST = 'localhost'

# Timer
MAX_TIME_LIMIT = 120
SOURCE_TIME_LIMIT = 30
FOTA_TIME_LIMIT = 260
AOTA_TIME_LIMIT = 500
SOTA_TIME_LIMIT = 900
POTA_TIME_LIMIT = FOTA_TIME_LIMIT + SOTA_TIME_LIMIT

# Command Constant
COMMAND_SUCCESS = "SUCCESS"
COMMAND_FAIL = "FAIL"

# MQTT topic
INBM_INSTALL_CHANNEL = 'manageability/request/install'

# Signature Tag Name
FOTA_SIGNATURE = "fota_signature"
SIGNATURE = "signature"

PATH_STRING = "Path"
