"""
    Constants and other config variables used throughout the AOTA module

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

# Device local cache
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_CACHE_PATH_PREFIX
from enum import Enum

REPOSITORY_TOOL_CACHE = str(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX / 'repository-tool')

# Docker compose cache
DOCKER_COMPOSE_CACHE = str(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX / 'dispatcher-docker-compose/')

DOCKER = 'docker'
COMPOSE = 'compose'
APPLICATION = 'application'

DockerCommands = Enum('DockerCommands', 'import load pull remove stats list')
ComposeCommands = Enum('ComposeCommands', 'up pull down list remove')
ApplicationCommands = Enum('ApplicationCommands', 'update')

# CentOS driver path in docker
CENTOS_DRIVER_PATH = "/host/inb_driver/"

# Supported driver upgrade


class SupportedDriver(Enum):
    XLINK = "thb-hddl-xlink-pci-net-driver"
    FLASH_LOGIC = "thb-flash-logic-driver"
