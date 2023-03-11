"""
    Constants for response messages to requests.
    Used by INBC to detect ota message.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

# Success message
# SUCCESSFUL_INSTALL for older INB release (before ER47)
SUCCESSFUL_INSTALL = "SUCCESSFUL INSTALL"
COMMAND_SUCCESSFUL = "COMMAND SUCCESSFUL"
# SOTA_COMMAND_STATUS_SUCCESS for older INB release (before ER47)
SOTA_COMMAND_STATUS_SUCCESS = "Overall SOTA status: Success"
SOTA_COMMAND_STATUS_SUCCESSFUL = "SOTA command status: SUCCESSFUL"
FLASHLESS_OTA_SUCCESS_MSG = "FLASHLESS OTA COMMAND SUCCESSFUL"
FOTA_SOTA_SUCCESS_MESSAGE_LIST = [SUCCESSFUL_INSTALL, COMMAND_SUCCESSFUL,
                                  SOTA_COMMAND_STATUS_SUCCESS, SOTA_COMMAND_STATUS_SUCCESSFUL]

# Failure message
FAILED_TO_INSTALL = "FAILED TO INSTALL"
SOTA_FAILURE = "Final result in SOTA execution: SOTA fail"
SOTA_COMMAND_FAILURE = "SOTA command status: FAILURE"
OTA_FAILURE = "OTA FAILURE"
INSTALL_CHECK_FAILURE = "Install check failed"
ERROR_DURING_INSTALL = "Error during install"
SOTA_OVERALL_FAILURE = "Overall SOTA status: Failure"
NO_NODES_FAILURE = "ERROR! No eligible nodes found"
FOTA_INPROGRESS_FAILURE = "An update is currently in progress"
FOTA_SOTA_FAILURE_MESSAGE_LIST = [FAILED_TO_INSTALL, OTA_FAILURE, INSTALL_CHECK_FAILURE,
                                  ERROR_DURING_INSTALL, SOTA_COMMAND_FAILURE, SOTA_OVERALL_FAILURE,
                                  SOTA_FAILURE]

RESTART_SUCCESS = "Restart Command Success"
QUERY_SUCCESS = "Registry query: SUCCESSFUL"
QUERY_HOST_SUCCESS = "MANIFEST PUBLISH SUCCESSFUL"

# Failure message
FAILED_TO_INSTALL = "FAILED TO INSTALL"


RESTART_FAILURE = "Restart FAILED"
QUERY_FAILURE = "Registry query FAILED"
QUERY_HOST_FAILURE = "Error"
QUERY_HOST_KEYWORD = "queryEndResult"
OTA_IN_PROGRESS = "Please try again after"
# ACTIVE_NODE_NOT_FOUND for older version of vision-agent (1.7.1 and older)
ACTIVE_NODE_NOT_FOUND = "No active nodes found"
ELIGIBLE_NODE_NOT_FOUND = "No eligible nodes found"

# Other message
DYNAMIC_TELEMETRY = "dynamic_telemetry"
DBS_LOG = "DBS"
DOCKER_NAME = "Docker"
DOCKER_MESSAGE = "docker"
