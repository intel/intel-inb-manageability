"""
    Constants used by both inbm-vision and inbm.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
 """
from datetime import datetime

UNKNOWN = 'Unknown'
UNKNOWN_DATETIME = datetime.strptime("9999-01-01", "%Y-%m-%d")

VALID_MAGIC_FILE_TYPE_PREFIXES = ['data', 'POSIX tar archive', 'gzip compressed data', 'exported SGML document',
                                  'ASCII text', 'PEM certificate', 'empty', 'u-boot legacy uImage',
                                  'Intel serial flash for PCH ROM', 'XML 1.0 document', 'Debian binary', 'RPM ']

TEMP_EXT_FOLDER = "/var/cache/manageability/repository-tool/temp_ext"
URL_NULL_CHAR = '%00'

# MQTT Channels
RESPONSE_CHANNEL = 'manageability/response'
EVENT_CHANNEL = 'manageability/event'
TELEMETRY_CHANNEL = 'manageability/telemetry'
CONFIG_CHANNEL = 'ma/configuration/update/'

# Request constants
CONFIG_LOAD = "load"
CONFIG_APPEND = "append"
CONFIG_REMOVE = "remove"

# Source
LOCAL_SOURCE = 'local'
REMOTE_SOURCE = 'remote'

# DMI path
DMI_PATH = '/sys/devices/virtual/dmi/'
FW_DMI_PATH = '/sys/devices/virtual/dmi/id/'
DMI_BIOS_RELEASE_DATE = 'bios_date'
DMI_BIOS_VENDOR = 'bios_vendor'
DMI_BIOS_VERSION = 'bios_version'
DMI_SYSTEM_MANUFACTURER = 'sys_vendor'
DMI_SYSTEM_PRODUCT_NAME = 'product_name'
# Used for systems gathering firmware info from dmi path
# Integration-tests
FW_DMI_IT_PATH = '/scripts/dmi_id_bios_info/'

# Used for systems implementing device-tree
DEVICE_TREE_PATH = '/proc/device-tree/'
DEVICE_TREE_MODEL = 'model'
BIOS_RELEASE_DATE = 'bios-release-date'
BIOS_VENDOR = 'bios-vendor'
BIOS_VERSION = 'bios-version'
SYSTEM_MANUFACTURER = 'system-manufacturer'
SYSTEM_PRODUCT_NAME = 'system-product-name'
FW_DEVICE_TREE_PATH = '/proc/device-tree/firmware/bios/'

# Afulnx tool name
AFULNX_64 = 'afulnx_64'

# Default signature version
DEFAULT_HASH_ALGORITHM = 384
