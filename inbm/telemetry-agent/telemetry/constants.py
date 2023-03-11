"""
    Constants and other config variables used throughout the telemetry module

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_ETC_PATH_PREFIX, BROKER_ETC_PATH, \
    INTEL_MANAGEABILITY_SHARE_PATH_PREFIX
from inbm_common_lib.utility import get_canonical_representation_of_path

AGENT = 'telemetry'
STATE_CHANNEL = '+/state'

DEFAULT_LOGGING_PATH = INTEL_MANAGEABILITY_ETC_PATH_PREFIX / \
    'public' / 'telemetry-agent' / 'logging.ini'

# PMS library path
PMS_LIB_PATH = "/usr/lib/"

# RM deamon path
RM_PATH = "/var/rm-daemon"

# Used for systems implementing device-tree
DEVICE_TREE_PATH = '/proc/device-tree/'
DEVICE_TREE_MODEL = 'model'

FW_DEVICE_TREE_PATH = '/proc/device-tree/firmware/bios/'
BIOS_RELEASE_DATE = 'bios-release-date'
BIOS_VENDOR = 'bios-vendor'
BIOS_VERSION = 'bios-version'
SYSTEM_MANUFACTURER = 'system-manufacturer'
SYSTEM_PRODUCT_NAME = 'system-product-name'

# Subscription channels
TELEMETRY_UPDATE_CHANNEL = 'telemetry/update'
CONFIGURATION_UPDATE_CHANNEL = 'configuration/update/telemetry/+'
DIAGNOSTIC_RESP_CHANNEL = 'diagnostic/response/'
CLOUDADAPTER_STATE_CHANNEL = 'cloudadapter/state'

# Publish channels
DIAGNOSTIC_CMD_CHANNEL = 'diagnostic/command/'
EVENTS_CHANNEL = 'manageability/event'

# TEST URL
TEST_URL = "google.com"

# Configuration paths
COLLECTION_INTERVAL_SECONDS = 'telemetry/collectionIntervalSeconds'
PUBLISH_INTERVAL_SECONDS = 'telemetry/publishIntervalSeconds'
MAX_CACHE_SIZE = 'telemetry/maxCacheSize'
CONTAINER_HEALTH_INTERVAL_SECONDS = 'telemetry/containerHealthIntervalSeconds'
SOFTWARE_BOM_INTERVAL_HOURS = 'telemetry/swBomIntervalHours'
ENABLE_SOFTWARE_BOM = 'telemetry/enableSwBom'

# Client certs and keys path
CLIENT_CERTS = BROKER_ETC_PATH / \
    'public' / 'telemetry-agent' / 'telemetry-agent.crt'
CLIENT_KEYS = BROKER_ETC_PATH / \
    'secret' / 'telemetry-agent' / 'telemetry-agent.key'

# Keys used to get temperature info on different platforms
TEMPERATURE_KEYS = ['coretemp', 'soc', 'cpu_n', 'cpu_s']

# swbom
MENDER_PATH = get_canonical_representation_of_path('/etc/mender/artifact_info')
UNKNOWN = 'Unknown'

# Software BOM list bytes to send at a time
SWBOM_BYTES_SIZE = 2500

SCHEMA_LOCATION = str(INTEL_MANAGEABILITY_SHARE_PATH_PREFIX /
                      'dispatcher-agent' / 'manifest_schema.xsd')
