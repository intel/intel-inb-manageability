"""
    Constants used by the common manageability library
    @copyright: Copyright 2021 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""
from inbm_common_lib.utility import get_canonical_representation_of_path

COMPOSE = 'compose'
DOCKER = 'docker'

# Docker stats telemetry key
DOCKER_STATS = 'containerStats'

# XML parse time limit
PARSE_TIME_SECS = 5

# TRTL install location
TRTL_PATH = get_canonical_representation_of_path('/usr/bin/trtl')

# Mender file path
MENDER_FILE_PATH = get_canonical_representation_of_path('/usr/bin/mender')

# system_is_Yocto file path (present on our Yocto packaging)
SYSTEM_IS_YOCTO_PATH = get_canonical_representation_of_path(
    '/usr/share/intel-manageability/system_is_Yocto')

# Force Yocto path
FORCE_YOCTO_PATH = get_canonical_representation_of_path('/etc/force_yocto')

# Path to inbm version files
INBM_VERSION_FILE = get_canonical_representation_of_path(
    '/usr/share/intel-manageability/inbm-version.txt')
INBM_VISION_VERSION_FILE_HOST = get_canonical_representation_of_path(
    '/usr/share/intel-manageability/inbm-vision-host-version.txt')
INBM_VISION_VERSION_FILE_NODE = get_canonical_representation_of_path(
    '/usr/share/intel-manageability/inbm-vision-node-version.txt')

# CentOS version path
CENTOS_VERSION_PATH = get_canonical_representation_of_path('/etc/centos-release')

# QUERY
QUERY_CMD_CHANNEL = 'dispatcher/query'
HOST_QUERY_CHANNEL = 'manageability/request/query'
