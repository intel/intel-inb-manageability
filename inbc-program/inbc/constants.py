""" Constants and other config variables used throughout the inbc module.

    Copyright (C) 2020-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_vision_lib.path_prefixes import BROKER_ETC_PATH

# certs
CLIENT_CERTS = str(BROKER_ETC_PATH / 'public' / 'inbc-program' / 'inbc-program.crt')
CLIENT_KEYS = str(BROKER_ETC_PATH / 'secret' / 'inbc-program' / 'inbc-program.key')
CA_CERTS = str(BROKER_ETC_PATH / 'public' / 'mqtt-ca' / 'mqtt-ca.crt')

# MQTT constant
MQTT_HOST = 'localhost'

# Timer
MAX_TIME_LIMIT = 120
FOTA_TIME_LIMIT = 260
SOTA_TIME_LIMIT = 900
POTA_TIME_LIMIT = FOTA_TIME_LIMIT + SOTA_TIME_LIMIT

# Xlink constants
XLINK_STATUS_CHECKING_INTERVAL = 5
MAX_STATUS_NUM = 300
DRIVER_NOT_FOUND = 5

# Command Constant
COMMAND_SUCCESS = "SUCCESS"
COMMAND_FAIL = "FAIL"

# MQTT topic
INBM_INSTALL_CHANNEL = 'manageability/request/install'

# Signature Tag Name
FOTA_SIGNATURE = "fota_signature"
SIGNATURE = "signature"

TARGETS_HELP = 'List of targets to be updated.  Use only if specific targets are to be updated.'
TARGETS_NODE_AND_CLIENT_ONLY_HELP = 'List of targets to be updated if target type is [node or node-client].  ' \
                                    'Use only if specific targets are to be updated and not all nodes or node-clients.'
TARGETS_NODE_ONLY_HELP = 'List of targets to restart if target type is [node].  Use this only if needing to restart ' \
                         'on specific targets and not all nodes.'
PATH_STRING = "Path"
VISION_SERVICE_PATH = "/lib/systemd/system/inbm-vision.service"
HDDL = "hddl"

# Target type
NODE = "node"
