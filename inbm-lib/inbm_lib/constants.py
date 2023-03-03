"""
    Constants used by the common manageability library
    @copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
    @license: SPDX-License-Identifier: Apache-2.0
"""
from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_CACHE_PATH_PREFIX

COMPOSE = 'compose'
DOCKER = 'docker'

# Docker stats telemetry key
DOCKER_STATS = 'containerStats'

# Command prefix to run a command 'as the host' using docker, chroot, and namespace control
# note this will not propagate proxy environment variables
# change above comment if -e entries are added for proxies
DOCKER_CHROOT_PREFIX = "/usr/bin/docker run -e DEBIAN_FRONTEND=noninteractive --privileged --rm --net=host --pid=host -v /:/host ubuntu:20.04 /usr/sbin/chroot /host "

# Command prefix to run a command simply in a chroot in the container without docker
# this will propagate all environment variables
CHROOT_PREFIX = "/usr/sbin/chroot /host "

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

# OTA types
FOTA = "fota"
SOTA = "sota"
POTA = "pota"

RESTART = "restart"
QUERY = "query"

OTA_UPDATE = "install"
PROVISION = 'provision'
REQUEST_CHANNEL = 'ma/request/'
INSTALL_CHANNEL = REQUEST_CHANNEL + OTA_UPDATE
RESTART_CHANNEL = REQUEST_CHANNEL + RESTART
QUERY_CHANNEL = REQUEST_CHANNEL + QUERY
PROVISION_CHANNEL = REQUEST_CHANNEL + PROVISION

# Device local cache
CACHE = str(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX / 'repository-tool/')
