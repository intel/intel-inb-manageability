# -*- coding: utf-8 -*-
"""
    Constants and other config variables used throughout the node-agent

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_common_lib.validater import ConfigurationItem

AGENT = 'node'
STATE_CHANNEL = '+/state'

# Subscription channels
CONFIGURATION_RESP_CHANNEL = 'configuration/response'

# Publish channels
REQUEST_CHANNEL = 'manageability/request/install'

# Supported HW Platforms
ARM = "aarch64"

# Supported OS Types
UBUNTU = "Ubuntu"
YOCTO = "Yocto"

# Client certs and keys path
CLIENT_CERTS = '/etc/intel-manageability/public/node-agent/node-agent.crt'
CLIENT_KEYS = '/etc/intel-manageability/secret/node-agent/node-agent.key'

# CMDLINE path to check verity status
CMDLINE_FILE_PATH = '/proc/cmdline'
VERITY_ENABLED = 'verity=1'
VERITY_DISABLED = 'verity=0'

# Measured boot path to check whether the TBH platform is measured boot.
MEASURED_BOOT_PATH = '/sys/firmware/devicetree/base/boot_info/measured_boot'

# Used by FOTA device tree
DEVICE_TREE_PATH = '/proc/device-tree/firmware/bios/'
BIOS_RELEASE_DATE = 'bios-release-date'
BIOS_VENDOR = 'bios-vendor'
BIOS_VERSION = 'bios-version'
SYSTEM_MANUFACTURER = 'system-manufacturer'
SYSTEM_PRODUCT_NAME = 'system-product-name'

# Invoker constants
INVOKER_QUEUE_SIZE = 30

# Used to download file
REQUEST_TO_DOWNLOAD_NAME = "Request To Download"
REGISTER_COMMAND_NAME = "Register Command"
SEND_HEARTBEAT_COMMAND = "Send Heartbeat Command"
HEARTBEAT_INTERVAL_SECS_NAME = "Request Heartbeat"
REQUEST_IS_ALIVE_COMMAND_NAME = "Request Heartbeat"
SEND_DOWNLOAD_STATUS_NAME = "Send Download Status Command"
OTA_UPDATE_COMMAND_NAME = "Ota Update Command"

# Schema and configuration location
SCHEMA_LOCATION = '/usr/share/node-agent/manifest_schema.xsd'
CONFIG_LOCATION = '/etc/intel-manageability/public/node-agent/intel_manageability_node.conf'
CONFIG_SCHEMA_LOCATION = '/usr/share/node-agent/intel_manageability_node_schema.xsd'
XLINK_SCHEMA_LOCATION = '/usr/share/node-agent/node_xlink_schema.xsd'

# configuration
GET_ELEMENT = 'get'
SET_ELEMENT = 'set'
LOAD = 'load'
APPEND = 'append'
REMOVE = 'remove'

# Configuration Element
REGISTRATION_RETRY_TIMER_SECS = 'registrationRetryTimerSecs'
REGISTRATION_RETRY_LIMIT = 'registrationRetryLimit'
HEARTBEAT_RESPONSE_TIMER_SECS = 'heartbeatResponseTimerSecs'
FLASHLESS = 'flashless'
XLINK_PCIE_DEV_ID = 'XLinkPCIeDevID'

# Node Key constants
KEY_DICTIONARY = ['registrationRetryTimerSecs',
                  'registrationRetryLimit',
                  'XLinkPCIeDevID']

# Mender commands/arguments
MENDER_ARTIFACT_PATH = "/etc/mender/artifact_info"

# Flashless checker constants
MOUNTS_PATH = "/proc/mounts"
ROOTFS = "rootfs"

# Manifest
RESTART_MANIFEST = '<?xml version="1.0" encoding="utf-8"?><manifest><type>cmd</type><cmd>restart</cmd></manifest>'

# Proc version file path
PROC_VERSION = '/etc/version'

# Node version file path
NODE_VERSION_PATH = '/usr/share/node-agent/version.txt'

# Configuration items (key, lower bound, upper bound, default value)
CONFIG_REGISTRATION_RETRY_TIMER_SECS = ConfigurationItem('RegistrationRetry Timer Secs', 1, 60, 20)
CONFIG_HEARTBEAT_RESPONSE_TIMER_SECS = ConfigurationItem(
    'Heartbeat Response Timer Secs', 90, 1800, 300)
CONFIG_REGISTRATION_RETRY_LIMIT = ConfigurationItem('Registration Retry Limit', 3, 15, 8)

# Var directory
VAR_DIR = '/var'
