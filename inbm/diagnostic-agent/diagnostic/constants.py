"""
    Agent which monitors and reports the state of critical components of the framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from inbm_lib.constants import TRTL_PATH

from diagnostic.config_dbs import ConfigDbs
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_ETC_PATH_PREFIX, \
    INTEL_MANAGEABILITY_CACHE_PATH_PREFIX, BROKER_ETC_PATH

AGENT = 'diagnostic'
STATE_CHANNEL = '+/state'

# Subscribing channels
CONFIGURATION_UPDATE_CHANNEL = 'configuration/update/diagnostic/+'
ALL_AGENTS_UPDATE_CHANNEL = 'configuration/update/all/+'
CMD_CHANNEL = 'diagnostic/command/+'

# publishing channels
RESPONSE_CHANNEL = 'diagnostic/response/'
REMEDIATION_CONTAINER_CHANNEL = 'remediation/container'
REMEDIATION_IMAGE_CHANNEL = 'remediation/image'
EVENTS_CHANNEL = 'manageability/event'

# Config value paths
MIN_STORAGE_MB = 'diagnostic/minStorageMB'
MIN_MEMORY_MB = 'diagnostic/minMemoryMB'
MIN_POWER_PERCENT = 'diagnostic/minPowerPercent'
MANDATORY_SW_LIST = 'diagnostic/sotaSW'
DOCKER_BENCH_SECURITY_INTERVAL_SEC = 'diagnostic/dockerBenchSecurityIntervalSeconds'
NETWORK_CHECK = 'diagnostic/networkCheck'
DBS_MODE = 'all/dbs'

# Cache path
DEFAULT_MANAGEABILITY_CACHE_PATH = str(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX)

# Client certs and keys path
CLIENT_CERTS = str(BROKER_ETC_PATH / 'public' /
                   'diagnostic-agent' / 'diagnostic-agent.crt')
CLIENT_KEYS = str(BROKER_ETC_PATH / 'secret' /
                  'diagnostic-agent' / 'diagnostic-agent.key')

# TRTL EVENTS
TRTL_EVENTS = [TRTL_PATH, '-cmd=events']

# Default config values
DEFAULT_LOGGING_PATH = str(INTEL_MANAGEABILITY_ETC_PATH_PREFIX /
                           'public' / 'diagnostic-agent' / 'logging.ini')
DEFAULT_MIN_MEMORY_MB = 10
UPPER_BOUND_MEMORY_MB = 300
LOWER_BOUND_MEMORY_MB = 10
DEFAULT_MIN_POWER_PERCENT = 20
UPPER_BOUND_POWER_PERCENT = 25
LOWER_BOUND_POWER_PERCENT = 15
DEFAULT_MIN_STORAGE_MB = 100
UPPER_BOUND_STORAGE_MB = 150
LOWER_BOUND_STORAGE_MB = 75
DEFAULT_DOCKER_BENCH_SECURITY_INTERVAL_SEC = 900
UPPER_BOUND_DBS_INTERVAL_SEC = 18000
LOWER_BOUND_DBS_INTERVAL_SEC = 60
DEFAULT_DOCKER_BENCH_SECURITY_ENABLED = True
DEFAULT_DBS_MODE = ConfigDbs.WARN
DEFAULT_NETWORK_CHECK = 'true'

# DBS tuning
DBS_LAUNCH_DELAY_SECONDS = 60
