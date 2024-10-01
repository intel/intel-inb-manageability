"""
    Constants and other config variables used throughout the common module

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_RAW_ETC, INTEL_MANAGEABILITY_VAR_PATH_PREFIX

NEW_DISPATCHER_STATE_FILE = str(INTEL_MANAGEABILITY_VAR_PATH_PREFIX / 'dispatcher_state')
OLD_DISPATCHER_STATE_FILE = str(INTEL_MANAGEABILITY_RAW_ETC / 'dispatcher_state')
