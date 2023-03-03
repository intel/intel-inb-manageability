"""
    Constants and other config variables used throughout the packagemanager module

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

# Configuration command/response channel
CONFIGURATION_CMD_CHANNEL = 'configuration/command/'
CONFIGURATION_RESP_CHANNEL = 'configuration/response/'

# Configuration paths
TRUSTED_REPOSITORIES_LIST = 'trustedRepositories'

# Configuration paths that support append and remove
CONFIGURATION_APPEND_REMOVE_PATHS_LIST = [
    'sotaSW', 'trustedRepositories']
