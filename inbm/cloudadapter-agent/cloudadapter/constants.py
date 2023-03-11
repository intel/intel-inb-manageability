"""
Constants and other config variables used throughout the cloudadapter module

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""

from inbm_common_lib.constants import TELEMETRY_CHANNEL, RESPONSE_CHANNEL, EVENT_CHANNEL
from inbm_lib.constants import DOCKER_STATS
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_ETC_PATH_PREFIX
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_SHARE_PATH_PREFIX, BROKER_ETC_PATH

AGENT = 'cloudadapter'

LOGGERCONFIG = INTEL_MANAGEABILITY_ETC_PATH_PREFIX / 'public' / 'cloudadapter-agent' / 'logging.ini'
CLIENT_CERTS = BROKER_ETC_PATH / \
    'public' / 'cloudadapter-agent' / 'cloudadapter-agent.crt'
CLIENT_KEYS = BROKER_ETC_PATH / \
    'secret' / 'cloudadapter-agent' / 'cloudadapter-agent.key'


# Delay to sleep in seconds
SLEEP_DELAY = 1


# ========== Subscription channels


STATE_CHANNEL = '+/state'


class TC_TOPIC:
    STATE = tuple([STATE_CHANNEL])
    TELEMETRY = tuple([TELEMETRY_CHANNEL])
    EVENT = tuple([EVENT_CHANNEL, RESPONSE_CHANNEL])  # TODO: What's up with response?


# ========== Publishing channels


TC_REQUEST_CHANNEL = 'manageability/request/'

DECOMMISSION = 'decommission'
SHUTDOWN = 'shutdown'
RESTART = 'restart'
INSTALL = 'install'

# TODO: What are these two?
UNKNOWN = {'rc': 1, 'message': 'Unknown command invoked'}
PARSE_ERROR = {'rc': 1, 'message': 'Key not present in payload'}


# ========== All agent message strings


class MESSAGE:
    SHUTDOWN = "Initiated device shutdown"
    DECOMMISSION = "Device decommissioned"
    UPLOAD_SUCCESS = "File upload success"
    REBOOT = "Initiated device reboot"
    MANIFEST = "Manifest Update Triggered"
    AOTA = "AOTA Triggered"
    FOTA = "FOTA Triggered"
    SOTA = "SOTA Triggered"
    CONFIG = "Configuration Method Triggered"
    QUERY = "Query Method Triggered"

# ========== Cloud method bindings


class METHOD:
    MANIFEST = "triggerota"
    AOTA = "triggeraota"
    FOTA = "triggerfota"
    SOTA = "triggersota"
    CONFIG = "triggerconfig"
    SHUTDOWN = "shutdown_device"
    REBOOT = "reboot_device"
    DECOMMISSION = "decommission_device"
    UPLOAD = "file_upload"
    QUERY = "triggerquery"

# ========== Cloud configuration constants


# The adapter configuration file
ADAPTER_CONFIG_PATH = INTEL_MANAGEABILITY_ETC_PATH_PREFIX / \
    'secret' / 'cloudadapter-agent' / 'adapter.cfg'

# Log certain telemetry keys by default
LOGGED_TELEMETRY = {DOCKER_STATS, 'networkInformation',
                    'resourceMonitoring', 'resourceAlert', 'softwareBOM',
                    'queryResult', 'queryEndResult'}  # 'disk-information'


# ========== Azure configuration constants


# The port to which the AzureMQTTClient should connect
AZURE_MQTT_PORT = 8883
# The default expiration of a SAS token (seconds: one millenium)
AZURE_TOKEN_EXPIRATION = 31556952000
# Endpoint for device provisioning
AZURE_DPS_ENDPOINT = "https://global.azure-devices-provisioning.net"


# ========== Telit configuration constants


# An arbitrary ID used to verify the device ID
TELIT_APP_ID = "intel-manageability"

# Datetime formatting expected for telemetry
TELIT_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


# ========== Generic configuration constants


# The system path to the JSON schema
GENERIC_SCHEMA_PATH = INTEL_MANAGEABILITY_SHARE_PATH_PREFIX / \
    'cloudadapter-agent' / 'config_schema.json'
