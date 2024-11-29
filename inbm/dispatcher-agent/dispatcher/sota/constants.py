"""
    Constants and other config variables used throughout the SOTA module

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_CACHE_PATH_PREFIX
from inbm_common_lib.utility import get_canonical_representation_of_path

# Mender file path
MENDER_FILE_PATH = get_canonical_representation_of_path('/usr/bin/mender')

# Mender artifact path
MENDER_ARTIFACT_PATH = get_canonical_representation_of_path("/etc/mender/artifact_info")

# Tiber Update Tool file path
TIBER_UPDATE_TOOL_PATH = get_canonical_representation_of_path('/usr/bin/os-update-tool.sh')

# Release server access token path
RELEASE_SERVER_TOKEN_PATH = get_canonical_representation_of_path('/etc/intel_edge_node/tokens/release-service/'
                                                       'access_token')

SOTA_STATE = 'normal'

LOGPATH = '/var/lib/dispatcher/upload'

APT_SOURCES_LIST_PATH = get_canonical_representation_of_path('/etc/apt/sources.list')

PROCEED_WITHOUT_ROLLBACK_DEFAULT = False

# Device local cache for SOTA
SOTA_CACHE = str(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX / 'repository-tool' / 'sota')


FAILED = "Failed"
SUCCESS = "Success"

FILE = "FILE"
CLOUD = "CLOUD"

BTRFS = "btrfs"

# Constants for mapping failure_reason in granular log
FAILURE_REASON_UNSPECIFIED = "unspecified"
FAILURE_REASON_NO_FAILURE = "nofailure" # to be used for empty failure_reason in future if we plan to include the failure_reason field in the case of a successful update.
FAILURE_REASON_DOWNLOAD = "download"
FAILURE_REASON_BOOTLOADER = "bootloader"
FAILURE_REASON_INSUFFICIENT_STORAGE = "insufficientstorage"
FAILURE_REASON_RS_AUTHENTICATION = "rsauthentication"
FAILURE_REASON_SIGNATURE_CHECK = "signaturecheck"
FAILURE_REASON_UT_WRITE = "utwrite"
FAILURE_REASON_UT_BOOT_CONFIGURATION = "utbootconfiguration"
FAILURE_REASON_CRITICAL_SERVICES = "criticalservices"
FAILURE_REASON_INBM = "inbm"
FAILURE_REASON_OS_COMMIT = "oscommit"

# Keywords used to map failure reason
DOWNLOAD_ERROR_LIST = ["OTA Fetch Failed", "Error getting artifact size", "Download cancelled"]
BOOTLOADER_ERROR_LIST = ["Requested update version is the same as previous version installed", "System has not been properly updated; reverting"]
INSUFFICIENT_STORAGE_ERROR_LIST = ["Insufficient free space", "Pre OTA check failed"]
RS_AUTHENTICATION_ERROR_LIST = ["No JWT token", "Invalid URI or Token"]
SIGNATURE_CHECK_ERROR_LIST = ["Signature is None", "Signature checks failed"]
CRITICAL_SERVICES_ERROR = "Critical service failure"
INBM_ERROR_LIST = ["Source verification failed", "Repository does not exist"]
# UT related failure
UT_WRITE_ERROR = "/usr/bin/os-update-tool.sh -w -u"   # ut write error. TODO: low confident. Need to test it.
UT_BOOT_CONFIGURATION_ERROR = "/usr/bin/os-update-tool.sh -a"  # ut apply error TODO: low confident. Need to test it.
UT_OS_COMMIT_ERROR = "Failed to run UT commit command"  # ut commit error


