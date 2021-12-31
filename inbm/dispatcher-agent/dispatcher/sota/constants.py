"""
    Constants and other config variables used throughout the SOTA module

    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_CACHE_PATH_PREFIX
from inbm_common_lib.utility import get_canonical_representation_of_path

GET_UBUNTU_PKG_REPO = "dispatcher/sota/ubuntuAptSource"

SOTA_STATE = 'normal'

LOGPATH = '/var/lib/dispatcher/upload'

APT_SOURCES_LIST_PATH = get_canonical_representation_of_path('/etc/apt/sources.list')

PROCEED_WITHOUT_ROLLBACK_DEFAULT = False

# Device local cache for SOTA
SOTA_CACHE = str(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX / 'repository-tool' / 'sota')

# Mender file path
MENDER_FILE_PATH = get_canonical_representation_of_path('/usr/bin/mender')

# Mender commands/arguments
MENDER_COMMAND = MENDER_FILE_PATH
MENDER_INSTALL_ARGUMENT = "-install"
MENDER_MINIMIZE_LOGS_ARGUMENT = "-log-level panic"
MENDER_ARTIFACT_PATH = get_canonical_representation_of_path("/etc/mender/artifact_info")
MENDER_COMMIT_COMMAND = "mender -commit"
MENDER_UPDATE_SCRIPT_EHL = "/etc/mender/scripts/ArtifactInstall_Leave_00_relabel_ext4"
MENDER_ARTIFACT_INSTALL_COMMAND = MENDER_UPDATE_SCRIPT_EHL

FAILED = "Failed"
SUCCESS = "Success"

FILE = "FILE"
CLOUD = "CLOUD"

BTRFS = "btrfs"

SOTA_FAILED_RESULT = "Final result in SOTA execution: SOTA fail"
