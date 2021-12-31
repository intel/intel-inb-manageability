# -*- coding: utf-8 -*-
"""
    Constants and other config variables used throughout the vision-agent.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from inbm_vision_lib.path_prefixes import INBM_VISION_ETC_PATH_PREFIX, INBM_VISION_SHARE_PATH_PREFIX, \
    INBM_VISION_USR_BIN_PREFIX, BROKER_ETC_PATH


class VisionException(Exception):
    """Vision exception module"""
    pass


AGENT = 'vision'
STATE_CHANNEL = '+/state'

# Subscription channels
CONFIGURATION_UPDATE_CHANNEL = 'ma/configuration/update/+'

# Publish channels
STATE_CHANNEL = 'vision/state/'
CONFIGURATION_COMMAND_CHANNEL = 'ma/configuration/command/'

# Client certs and keys path
CLIENT_CERTS = str(BROKER_ETC_PATH/'public'/'vision-agent'/'vision-agent.crt')
CLIENT_KEYS = str(BROKER_ETC_PATH/'secret'/'vision-agent'/'vision-agent.key')

# Logging file path
DEFAULT_LOGGING_PATH = str(INBM_VISION_ETC_PATH_PREFIX /
                           'public' / 'vision-agent' / 'logging.ini')

# Status Codes
FAILURE = 400
SUCCESS = 200

# Timer constants
RESTART_TIMER_SECS = 420  # TODO:  Needs to be in Vision-agent configuration file
FLASHLESS_BOOT_TIME_SECS = 240

# Heartbeat constants
HEARTBEAT_CHECK_INTERVAL = 300  # 5 minutes
NODE_HEARTBEAT_INTERVAL = 60  # 1 minute
HEARTBEAT_RETRY_LIMIT = 3
HEARTBEAT_ACTIVE_STATE = "Active"
HEARTBEAT_IDLE_STATE = "Idle"
IS_ALIVE_CHECK_INTERVAL = 180  # 3 minutes
INTERNAL_CLOCK_INTERVAL = 1

# Update constants
UPDATE_SUCCESS_STATE = "Success"
UPDATE_FAIL_STATE = "Fail"
CONVERSION_TO_KB = 10
VISION_ID = "000"

# Invoker constants
INVOKER_QUEUE_SIZE = 100

# Maximum OTA and load timer
MAX_CONFIG_LOAD_TIMER_SECS = 120
MAX_FOTA_TIMER_SECS = 600
MAX_SOTA_TIMER_SECS = 900
MAX_POTA_TIMER_SECS = 900

# Command constants
UPDATE_NODE_COMMAND_NAME = "Update Node Command"
SEND_REGISTRATION_CONFIRMATION_NAME = "Send Registration Confirmation Command"
SEND_ISALIVE_COMMAND_NAME = "Send IsAlive Command"
SEND_TELEMETRY_EVENT_COMMAND_NAME = "Send Telemetry Event Command"
UPDATE_NODE_HEARTBEAT_COMMAND_NAME = "Update Node Heartbeat Command"
REGISTER_NODE_COMMAND_NAME = "Register Node Command"
UPDATE_SENDER_COMMAND_NAME = "Update Sender Command"
SEND_TELEMETRY_RESPONSE_COMMAND_NAME = "Send Telemetry Response Command"
SEND_DOWNLOAD_REQUEST_COMMAND_NAME = "Send Download Request Command"
SEND_OTA_MANIFEST_COMMAND_NAME = "Send Ota Manifest Command"
SEND_OTA_FILE_COMMAND_NAME = "Send Ota File Command"
RECEIVE_DOWNLOAD_RESPONSE_NAME = "Receive Download Response"
RECEIVE_REQUEST_DOWNLOAD_RESPONSE_NAME = "Receive Request Download Response"
NO_ACTIVE_NODES_FOUND_ERROR = "ERROR! No eligible nodes found to perform the requested update."

# Schema and config location
SCHEMA_LOCATION = str(INBM_VISION_SHARE_PATH_PREFIX/'vision-agent'/'manifest_schema.xsd')
CONFIG_LOCATION = str(INBM_VISION_ETC_PATH_PREFIX/'public' /
                      'vision-agent'/'intel_manageability_vision.conf')
CONFIG_SCHEMA_LOCATION = str(INBM_VISION_SHARE_PATH_PREFIX /
                             'vision-agent'/'intel_manageability_vision_schema.xsd')
XLINK_SCHEMA_LOCATION = str(INBM_VISION_SHARE_PATH_PREFIX/'vision-agent'/'vision_xlink_schema.xsd')

# XLink device status
XLINK_STATUS_CHECKING_INTERVAL = 2

# Xlink provision directory (for TBH blob/cert provisioning)
XLINK_PROVISION_PATH = '/opt/xlink_provision'

# Flashless tool path
FLASHLESS_TOOL_PATH = str(INBM_VISION_USR_BIN_PREFIX /
                          'vision-flashless' / 'flashless')

# XLink event type
DEVICE_DOWN = "0"
DEVICE_UP = "1"
