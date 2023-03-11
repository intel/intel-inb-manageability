"""
    Constants and other config variables used throughout the configuration module

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_ETC_PATH_PREFIX, \
    INTEL_MANAGEABILITY_RAW_ETC, INTEL_MANAGEABILITY_SHARE_PATH_PREFIX, BROKER_ETC_PATH

AGENT = 'configuration'
STATE_CHANNEL = '+/state'

DEFAULT_LOGGING_PATH = str(INTEL_MANAGEABILITY_ETC_PATH_PREFIX /
                           'public' / 'configuration-agent' / 'logging.ini')

# Subscription channels
COMMAND_CHANNEL = 'configuration/command/+'

# Publish channels
UPDATE_CHANNEL = 'configuration/update/'
RESPONSE_CHANNEL = 'configuration/response/'

# Schema location
SCHEMA_LOCATION = str(INTEL_MANAGEABILITY_SHARE_PATH_PREFIX / (AGENT + '-agent') /
                      'iotg_inb_schema.xsd')
CONFIG_SCHEMA_LOCATION = str(INTEL_MANAGEABILITY_SHARE_PATH_PREFIX / (AGENT + '-agent') /
                             'inb_config_schema.xsd')
XML_LOCATION = str(INTEL_MANAGEABILITY_RAW_ETC / 'intel_manageability.conf')
CONFIG_LOCATION = str(INTEL_MANAGEABILITY_RAW_ETC / 'tc_config.conf')

# Agents requiring updates
AGENTS = ['diagnostic', 'telemetry', 'dispatcher', 'sota', 'all']

# Workload-Orchestration configuration tags
ORCHESTRATOR = 'orchestrator'
ATTRIB_NAME = 'name'

# Client certs and keys path
CLIENT_CERTS = str(BROKER_ETC_PATH / 'public' /
                   'configuration-agent' / 'configuration-agent.crt')
CLIENT_KEYS = str(BROKER_ETC_PATH / 'secret' /
                  'configuration-agent' / 'configuration-agent.key')
