# -*- coding: utf-8 -*-
"""
    This module is to check the current node package installed on Yocto system.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Optional
from node.constant import NODE_VERSION_PATH

logger = logging.getLogger(__name__)


def get_version() -> Optional[str]:
    """Helper function for getting version of node agent in the system

    @return: version of node agent
    """
    logger.debug("")
    try:
        with open(NODE_VERSION_PATH, 'r') as version_file:
            node_pkg_version = version_file.readlines()[0].replace('\n', '')
    except (FileNotFoundError, PermissionError) as error:
        logger.error("Failed to get node version with error: {0}".format(error))
        node_pkg_version = 'UNKNOWN'
    finally:
        return node_pkg_version
