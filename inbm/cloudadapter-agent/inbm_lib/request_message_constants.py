"""
    Constants for OTA related message.
    Used by INBC to detect OTA message.

    Copyright (C) 2019-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
# CONFIGURATION_SUCCESSFUL_OLD for older INB release (before ER47)
CONFIGURATION_SUCCESSFUL_OLD = "Configuration update: successful"
CONFIGURATION_SUCCESSFUL = "Configuration command: SUCCESSFUL"
CONFIGURATION_GET_SUCCESSFUL = "Configuration get_element command: SUCCESSFUL"
CONFIGURATION_SET_SUCCESSFUL = "Configuration set_element command: SUCCESSFUL"
CONFIGURATION_LOAD_SUCCESSFUL = "Configuration load: SUCCESSFUL"
CONFIGURATION_LOAD_SUCCESSFUL_OLD = "Configuration load: successful"
CONFIGURATION_SUCCESSFUL_MESSAGE_LIST = [CONFIGURATION_SUCCESSFUL, CONFIGURATION_GET_SUCCESSFUL,
                                         CONFIGURATION_SET_SUCCESSFUL, CONFIGURATION_LOAD_SUCCESSFUL,
                                         CONFIGURATION_SUCCESSFUL_OLD, CONFIGURATION_LOAD_SUCCESSFUL_OLD]

# CONFIGURATION_UNSUCCESSFUL for older INB release (before ER47)
CONFIGURATION_UNSUCCESSFUL = "Configuration update: unsuccessful"
CONFIGURATION_FAILURE = "Configuration command: FAILED"
CONFIGURATION_GET_FAILURE = "Configuration get_element command: FAILED"
CONFIGURATION_SET_FAILURE = "Configuration set_element command: FAILED"
CONFIGURATION_LOAD_FAILURE = "Configuration load: FAILED"
# CONFIGURATION_LOAD_UNSUCCESSFUL for older INB release (before ER47)
CONFIGURATION_LOAD_UNSUCCESSFUL = "Configuration load: unsuccessful"
CONFIGURATION_FAILURE_MESSAGE_LIST = [CONFIGURATION_FAILURE, CONFIGURATION_GET_FAILURE, CONFIGURATION_SET_FAILURE,
                                      CONFIGURATION_LOAD_FAILURE, CONFIGURATION_UNSUCCESSFUL,
                                      CONFIGURATION_LOAD_UNSUCCESSFUL]

NODE_NOT_FOUND = "No active nodes found"

# Other message
NUM_TARGET = "OTA_TARGETS:"
NO_DEVICE_FOUND = "No xlink PCIe device found. Please install xlink driver. Will detect again in 30 seconds."
