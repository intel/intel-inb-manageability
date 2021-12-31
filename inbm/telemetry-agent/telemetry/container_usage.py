"""
    Central telemetry/logging service for the manageability framework 

    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import json
from typing import Optional
from future import standard_library
from inbm_lib.trtl import Trtl
standard_library.install_aliases()

# TODO: let command line change this (maybe default to INFO); unit tests should stay DEBUG

logger = logging.getLogger(__name__)


class ContainerUsage:
    """Class for retrieving and parsing container usage information.

    @param trtl: TRTL object
    """

    def __init__(self, trtl: Trtl) -> None:
        self.__trtl = trtl

    def get_container_usage(self) -> Optional[str]:
        """Calls TRTL object's stats API

        @return: Container usage information if usage information exists; otherwise, None.
        """
        usage = self.__trtl.stats()
        if usage is not None:
            return usage if _create_cpu_usages_string(usage) else None
        return usage


def _create_cpu_usages_string(data: str) -> Optional[str]:
    try:
        return json.loads(data)
    except ValueError as err:
        logger.exception('Unable to parse JSON string %s from TRTL: %s', data, err)
        return None
