"""
    Constants and other config variables used throughout the dispatcher module

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from enum import Enum

from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_ETC_PATH_PREFIX, \
    INTEL_MANAGEABILITY_SHARE_PATH_PREFIX, INTEL_MANAGEABILITY_CACHE_PATH_PREFIX, BROKER_ETC_PATH

AGENT = 'dispatcher'
STATE_CHANNEL = '+/state'

DEFAULT_LOGGING_PATH = str(INTEL_MANAGEABILITY_ETC_PATH_PREFIX /
                           'public' / 'dispatcher-agent' / 'logging.ini')

PROCEED_WITHOUT_ROLLBACK_DEFAULT = False
HOST_WITH_NODES_DEFAULT = False

# Workload Orchestration
ORCHESTRATOR_RESPONSE_DEFAULT = False
CSL_CMD_STATUS_CODE = 202
CSL_POLL_CMD_STATUS_CODE = 200

# Configuration tags that supports workload orchestration services
ORCHESTRATOR = 'orchestrator'
ORCHESTRATOR_RESPONSE = 'orchestratorResponse'
IP = 'ip'
TOKEN = 'token'  # noqa: S105
CSL_CA = 'certFile'


# Subscription channels
TC_REQUEST_CHANNEL = 'manageability/request/+'
DIAGNOSTIC_RESP_CHANNEL = 'diagnostic/response/'
CONFIGURATION_DISPATCHER_UPDATE_CHANNEL = 'configuration/update/dispatcher/+'
CONFIGURATION_ALL_AGENTS_UPDATE_CHANNEL = 'configuration/update/all/+'
CONFIGURATION_SOTA_UPDATE_CHANNEL = 'configuration/update/sota/+'
TARGET_OTA_CMD_CHANNEL = 'ma/request/install'
TARGET_PROVISION = 'ma/request/provision'
TARGET_CMD_RESTART = 'ma/request/restart'
VISION_CMD_QUERY = 'ma/request/query'

# Publishing channels
CUSTOM_CMD_CHANNEL = 'manageability/cmd/custom'
DIAGNOSTIC_CMD_CHANNEL = 'diagnostic/command/'
TELEMETRY_UPDATE_CHANNEL = 'telemetry/update'

# Schema location
SCHEMA_LOCATION = str(INTEL_MANAGEABILITY_SHARE_PATH_PREFIX /
                      'dispatcher-agent' / 'manifest_schema.xsd')
JSON_SCHEMA_LOCATION = str(INTEL_MANAGEABILITY_SHARE_PATH_PREFIX /
                           'dispatcher-agent' / 'config_param_schema.json')

# Client certs and keys path
CLIENT_CERTS = str(BROKER_ETC_PATH / 'public' /
                   'dispatcher-agent' / 'dispatcher-agent.crt')
CLIENT_KEYS = str(BROKER_ETC_PATH / 'secret' /
                  'dispatcher-agent' / 'dispatcher-agent.key')

# OTA package check certificate path
OTA_PACKAGE_CERT_PATH = str(BROKER_ETC_PATH / 'public' /
                            'dispatcher-agent' / 'ota_signature_cert.pem')

# Test Adapter service
TEST_ADAPTER_AGENT = 'dispatcher'

# Device local cache
CACHE = str(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX)
REPO_CACHE = str(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX / 'repository-tool')

TargetType = Enum('TargetType', 'none vision node')

SUCCESS_RESTART = "Restart Command Success"

# File permission masks
UMASK_CONFIGURATION_FILE = 0o113  # 0o113 means prohibit execute by user or group, allow only read for other
UMASK_PROVISION_FILE = 0o113  # 0o113 means prohibit execute by user or group, allow only read for other
UMASK_OTA = 0o117  # 0o117 means prohibit execute by user or group, prohibit all for other


class OtaType(Enum):
    """Supported OTA types."""
    FOTA = 0
    SOTA = 1
    AOTA = 2
    POTA = 3
