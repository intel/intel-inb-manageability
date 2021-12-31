# -*- coding: utf-8 -*-
"""
    Stores configuration constants used throughout the vision-agent

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

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
KEY_MANIFEST = [VISION_HB_CHECK_INTERVAL_SECS,
                NODE_HEARTBEAT_INTERVAL_SECS,
                VISION_FOTA_TIMER,
                VISION_SOTA_TIMER,
                VISION_POTA_TIMER,
                IS_ALIVE_INTERVAL_SECS,
                VISION_HB_RETRY_LIMIT,
                FLASHLESS_FILE_PATH,
                XLINK_PCIE_DEV_ID,
                XLINK_FIRST_CHANNEL_ID,
                XLINK_LAST_CHANNEL_ID,
                XLINK_BOOT_DEV,
                FLASHLESS_OTA_BOOT_TIME,
                ROLLBACK_WAIT_TIME,
                BOOT_FLASHLESS_DEV
                ]

DEFAULT_ROLLBACK_WAIT_TIME = 600
