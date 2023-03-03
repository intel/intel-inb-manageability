"""
    Agent which monitors and reports the state of critical components of the framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import psutil

logger = logging.getLogger(__name__)


def is_between_bounds(value_desc: str, actual_value: int, lower_bound: int, upper_bound: int) -> bool:
    """Compare a string value to a lower and upper bound.  Log an error if the
    value is not an integer or is outside the bounds."""
    if actual_value < lower_bound or actual_value > upper_bound:
        logger.error(value_desc + " needs to be between " +
                     str(lower_bound) + " and " + str(upper_bound) + "; actual value is: " +
                     str(actual_value))
        return False
    return True


def get_free_memory() -> int:
    """Gets the amount of free memory on the device

    @return amount of free memory"""
    return psutil.virtual_memory().available
