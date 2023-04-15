"""
    Constants and other config variables used throughout the fota module

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
# Device local cache
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_CACHE_PATH_PREFIX, INTEL_MANAGEABILITY_RAW_ETC, \
    INTEL_MANAGEABILITY_SHARE_PATH_PREFIX
import datetime

FOTA_CONF_PATH = str(INTEL_MANAGEABILITY_RAW_ETC / 'firmware_tool_info.conf')
FOTA_CONF_SCHEMA_LOC = str(INTEL_MANAGEABILITY_SHARE_PATH_PREFIX /
                           'dispatcher-agent' / 'firmware_tool_config_schema.xsd')
# Used by FOTA device tree
DEVICE_TREE_PATH = '/proc/device-tree/firmware/bios/'
BIOS_RELEASE_DATE = 'bios-release-date'
BIOS_VENDOR = 'bios-vendor'
BIOS_VERSION = 'bios-version'
SYSTEM_MANUFACTURER = 'system-manufacturer'
SYSTEM_PRODUCT_NAME = 'system-product-name'

# Platform names
WINDOWS_NUC_PLATFORM = 'NUC7i5DNKPC'

# Magic numbers
DPINST_CODE_REBOOT = 0x40000001  # DPInst.exe code for 'one package or driver installed, need reboot'
# DPInst.exe code for 'one package or driver installed, do not need reboot'
DPINST_CODE_NO_REBOOT = 0x00000001
