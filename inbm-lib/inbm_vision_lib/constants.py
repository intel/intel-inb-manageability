"""
    Constants used by the common manageability library
    
    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from typing import Dict
from inbm_vision_lib.path_prefixes import INBM_VISION_CACHE_PATH_PREFIX, INBM_VISION_XLINK_PATH_PREFIX, INBM_VISION_XLINK_LIB_PATH, BROKER_ETC_PATH, INBM_VISION_XLINK_PROVISION_PATH_PREFIX


def create_error_message(error: str) -> Dict[str, str]:
    """Creates an error string using the dictionary format

    @param error: error message
    @return: Dictionary with error code and message
    """
    return {'status': '400', 'message': f'{error}'}


def create_success_message(message: str) -> Dict[str, str]:
    """Creates an success string using the dictionary format

    @param message: message
    @return: Dictionary with success code and message
    """
    return {'status': '200', 'message': f'{message}'}


class SecurityException(Exception):
    """Security exception module"""
    pass


class XmlException(Exception):

    """Class exception Module"""
    pass


UNKNOWN = 'Unknown'

# Xlink channels
UNSECURED_XLINK_CHANNEL = 0x501
SECURED_XLINK_CHANNEL = 0x601
MAXIMUM_STORE_FILE_SIZE = 1024 * 1024 * 10
XLINK_DATA_SIZE = 1096 * 1000 * 4
XLINK_SECURE_DATA_SIZE = 1000 * 1000 * 2
XLINK_FILE_TRANSFER_RATE = 5
XLINK_FIRST_CHANNEL = 0xAAA
XLINK_LAST_CHANNEL = 0xBBB

# XLink device status
XLINK_UNAVAILABLE = -1
XLINK_DEV_OFF = 0
XLINK_DEV_ERROR = 1
XLINK_DEV_BUSY = 2
XLINK_DEV_RECOVERY = 3
XLINK_DEV_READY = 4

# Xlink Paths
XLINK_LIB_PATH = str(INBM_VISION_XLINK_LIB_PATH)
SECURE_XLINK_LIB_PATH = str(INBM_VISION_XLINK_PATH_PREFIX / 'libSecureXLink.so')
SECURE_XLINK_PROVISION_LIB_PATH = str(INBM_VISION_XLINK_PROVISION_PATH_PREFIX / 'libSecureXLink_provision.so')
XLINK_SIMULATOR_PC_LIB_PATH = str(INBM_VISION_XLINK_PATH_PREFIX / 'libXLinkPC.so')
XLINK_SIMULATOR_ARM_LIB_PATH = str(INBM_VISION_XLINK_PATH_PREFIX / 'libXLinkARM.so')

# Xlink device/platform type
SW_DEVICE_ID_IPC_INTERFACE = 0x0
SW_DEVICE_ID_PCIE_INTERFACE = 0x1
SW_DEVICE_ID_USB_INTERFACE = 0x2
SW_DEVICE_ID_ETH_INTERFACE = 0x3
SW_DEVICE_ID_INTERFACE_MASK = 0x7
SW_DEVICE_ID_INTERFACE_SHIFT = 24
SW_DEVICE_ID_KMB = 0x0
SW_DEVICE_ID_TBH_PRIME = 0x1
SW_DEVICE_ID_TBH_FULL = 0x2
SW_DEVICE_ID_OYB = 0x3
SW_DEVICE_ID_MTL = 0x4
SW_DEVICE_ID_STF = 0x5
SW_DEVICE_ID_PLATFORM_MASK = 0xF
SW_DEVICE_ID_PLATFORM_SHIFT = 4

# Xlink boot device default value
XLINK_BOOT_DEV_DEFAULT = False

# Xlink maximum device's name size
MAXIMUM_DEVICE_NAME_SIZE = 128

# GUID minimum length
MINIMUM_GUID_LENGTH = 16

# GUID maximum buffer size
MAXIMUM_GUID_BUFFER = 250

# MQTT ca path
MQTT_CA_CERTS = str(BROKER_ETC_PATH/'public'/'mqtt-ca'/'mqtt-ca.crt')

# Device local cache
CACHE = str(INBM_VISION_CACHE_PATH_PREFIX / 'repository-tool/')
CACHE_MANAGEABILITY = str(INBM_VISION_CACHE_PATH_PREFIX / '')

# Error Messages
ERROR_UNINITIALIZED_OBJECT = "Uninitialized object"

# Used for systems implementing device-tree
DEVICE_TREE_PATH = '/proc/device-tree/'
DEVICE_TREE_MODEL = 'model'

FW_DEVICE_TREE_PATH = '/proc/device-tree/firmware/bios/'
BIOS_RELEASE_DATE = 'bios-release-date'
BIOS_VENDOR = 'bios-vendor'
BIOS_VERSION = 'bios-version'
SYSTEM_MANUFACTURER = 'system-manufacturer'
SYSTEM_PRODUCT_NAME = 'system-product-name'

PARSE_TIME_SECS = 5

# Request constants
OTA_UPDATE = "install"
CONFIG_SET = "set_element"
CONFIG_GET = "get_element"
CONFIG_APPEND = "append"
CONFIG_REMOVE = "remove"
RESTART = 'restart'
QUERY = 'query'
STATUS = 'status'
PROVISION = 'provision'

# Target types
VISION = "vision"
NODE = "node"
NODE_CLIENT = "node_client"

# OTA types
FOTA = "fota"
SOTA = "sota"
POTA = "pota"

PATH = "path"
TARGET = "target"
TARGET_TYPE = "targetType"

# Flashless constant
# The name of fip and os image may be different in other platform.
FLASHLESS_FILE_PATH = 'flashlessFileLocation'
FIP_FILE = 'thb_fip.bin'
OS_IMAGE = 'thb_os.bin'
ROOTFS = 'thb_rootfs.bin'
LIB_FIRMWARE_PATH = '/lib/firmware/'
FLASHLESS_BACKUP = LIB_FIRMWARE_PATH + 'flashless_backup'

# Supported OS Types
UBUNTU = "Ubuntu"
YOCTO = "Yocto"

# Platform Types
KMB = "KEEMBAY"
TBH = "THUNDERBAY"

# Time related constants
VISION_BUFFER_TIMEOUT = 30  # in seconds, 0 for infinitely
NODE_BUFFER_TIMEOUT = 60  # in seconds, 0 for infinitely
MAXIMUM_NUM_OF_CHUNK_TO_BE_TRANSFERRED_BEFORE_TIMEOUT = 100
MAXIMUM_WRITE_DATA_RETRY = 10

# vision-agent channel
VISION_REQUEST_CHANNEL = 'ma/request/'
INSTALL_CHANNEL = VISION_REQUEST_CHANNEL + OTA_UPDATE
RESTART_CHANNEL = VISION_REQUEST_CHANNEL + RESTART
QUERY_CHANNEL = VISION_REQUEST_CHANNEL + QUERY
PROVISION_CHANNEL = VISION_REQUEST_CHANNEL + PROVISION
DEVICE_STATUS_CHANNEL = 'ma/xlink/status'
