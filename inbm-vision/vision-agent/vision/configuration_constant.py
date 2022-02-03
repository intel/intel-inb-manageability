# -*- coding: utf-8 -*-
"""
    Stores configuration constants used throughout the vision-agent

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_common_lib.validater import ConfigurationItem

# Configuration items (key, lower bound, upper bound, default value)
CONFIG_HEARTBEAT_CHECK_INTERVAL_SECS = ConfigurationItem(
    'Heartbeat Check Interval Seconds', 10, 1200, 300)
CONFIG_HEARTBEAT_TRANSMISSION_INTERVAL_SECS = ConfigurationItem(
    'Heartbeat Transmission Interval Seconds', 10, 240, 60)
CONFIG_HEARTBEAT_RETRY_LIMIT = ConfigurationItem('Heartbeat Retry Limit', 2, 15, 3)
CONFIG_FOTA_COMPLETION_TIMER_SECS = ConfigurationItem(
    'FOTA Completion Timer Seconds', 120, 1200, 600)
CONFIG_SOTA_COMPLETION_TIMER_SECS = ConfigurationItem(
    'SOTA Completion Timer Seconds', 600, 1680, 900)
CONFIG_POTA_COMPLETION_TIMER_SECS = ConfigurationItem(
    'POTA Completion Timer Seconds', 600, 1680, 900)
CONFIG_IS_ALIVE_TIMER_SECS = ConfigurationItem('IsAlive Timer Seconds', 60, 600, 180)
CONFIG_FLASHLESS_ROLLBACK_WAIT_TIMER_SECS = ConfigurationItem(
    'Flash-less Rollback Wait Time Seconds', 120, 1200, 600)

DEFAULT_FLASHLESS_FILE_PATH = "/lib/firmware/"

# Configuration constants
VISION_HB_CHECK_INTERVAL_SECS = 'heartbeatCheckIntervalSecs'
NODE_HEARTBEAT_INTERVAL_SECS = 'heartbeatTransmissionIntervalSecs'
VISION_FOTA_TIMER = 'fotaCompletionTimerSecs'
VISION_SOTA_TIMER = 'sotaCompletionTimerSecs'
VISION_POTA_TIMER = 'potaCompletionTimerSecs'
IS_ALIVE_INTERVAL_SECS = 'isAliveTimerSecs'
VISION_HB_RETRY_LIMIT = 'heartbeatRetryLimit'
FLASHLESS_FILE_PATH = 'flashlessFileLocation'
XLINK_PCIE_DEV_ID = 'XLinkPCIeDevID'
XLINK_FIRST_CHANNEL_ID = 'xlinkFirstChannel'
XLINK_LAST_CHANNEL_ID = 'xlinkLastChannel'
XLINK_BOOT_DEV = 'xlinkBootDevice'
FLASHLESS_OTA_BOOT_TIME = 'flashlessOTABootTimeSecs'
ROLLBACK_WAIT_TIME = 'flashlessRollbackWaitTimeSecs'
BOOT_FLASHLESS_DEV = 'bootFlashlessDevice'

# Vision-agent Key constants
KEY_MANIFEST = [FLASHLESS_FILE_PATH,
                XLINK_PCIE_DEV_ID,
                XLINK_FIRST_CHANNEL_ID,
                XLINK_LAST_CHANNEL_ID,
                XLINK_BOOT_DEV,
                BOOT_FLASHLESS_DEV,
                ]
# Included separately to ensure values are integers.
INT_CONFIG_VALUES = [VISION_HB_CHECK_INTERVAL_SECS,
                     NODE_HEARTBEAT_INTERVAL_SECS,
                     VISION_FOTA_TIMER,
                     VISION_SOTA_TIMER,
                     VISION_POTA_TIMER,
                     IS_ALIVE_INTERVAL_SECS,
                     VISION_HB_RETRY_LIMIT,
                     FLASHLESS_OTA_BOOT_TIME,
                     ROLLBACK_WAIT_TIME,
                     ]

KEY_MANIFEST.extend(INT_CONFIG_VALUES)

DEFAULT_ROLLBACK_WAIT_TIME = 600
