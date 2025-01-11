"""
    Constants for response messages to requests.
    Used by INBC to detect ota message.

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

# Success message
# SUCCESSFUL_INSTALL for older INB release (before ER47)
SUCCESSFUL_INSTALL = "SUCCESSFUL INSTALL"
COMMAND_SUCCESSFUL = "COMMAND SUCCESSFUL"
SOTA_COMMAND_STATUS_SUCCESSFUL = "SOTA command status: SUCCESSFUL"

OTA_SUCCESS_MESSAGE_LIST = [SUCCESSFUL_INSTALL, COMMAND_SUCCESSFUL, SOTA_COMMAND_STATUS_SUCCESSFUL]

# Failure message
FAILED_TO_INSTALL = "FAILED TO INSTALL"
SOTA_FAILURE = "Final result in SOTA execution: SOTA fail"
SOTA_COMMAND_FAILURE = "SOTA command status: FAILURE"
OTA_FAILURE = "OTA FAILURE"
INSTALL_CHECK_FAILURE = "Install check failed"
ERROR_DURING_INSTALL = "Error during install"
FOTA_INPROGRESS_FAILURE = "An update is currently in progress"
OTA_FAILURE_MESSAGE_LIST = [FAILED_TO_INSTALL, OTA_FAILURE, INSTALL_CHECK_FAILURE,
                                  ERROR_DURING_INSTALL, SOTA_COMMAND_FAILURE, SOTA_FAILURE]

RESTART_SUCCESS = "Restart Command Success"
QUERY_SUCCESS = "Registry query: SUCCESSFUL"
MANIFEST_PUBLISH_SUCCESS = "MANIFEST PUBLISH SUCCESSFUL"
GET_POWER_STATE_SUCCESS = "Get power request: SUCCESSFUL"

# Failure message
FAILED_TO_INSTALL = "FAILED TO INSTALL"


RESTART_FAILURE = "Restart FAILED"
GET_POWER_STATE_FAILURE = "Get power request: FAILED"
QUERY_FAILURE = "Registry query FAILED"
FAILURE = "Error"
QUERY_HOST_KEYWORD = "queryEndResult"
OTA_IN_PROGRESS = "Please try again after"

# Other message
DYNAMIC_TELEMETRY = "dynamic_telemetry"
DBS_LOG = "DBS"
DOCKER_NAME = "Docker"
DOCKER_MESSAGE = "docker"
