"""
    Converts data sizes

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import enum
from typing import Union

logger = logging.getLogger(__name__)


def size_to_bytes(update_size: str) -> Union[float, int]:
    """Cleans the data and returns a sanitized size in bytes

    @param update_size: The dirty size from apt-commands
    @return: Returns in Bytes in float format.
    """
    logger.debug("")

    class ByteSize(enum.Enum):
        B = 0
        kB = 3
        mB = 6
        gB = 9
        KB = kB
        MB = mB
        GB = gB

    temp_size = update_size.split()
    power = ByteSize[temp_size[1]]
    return (float(temp_size[0]) if temp_size[0].find('.')
            else int(temp_size[0])) * 10 ** power.value
