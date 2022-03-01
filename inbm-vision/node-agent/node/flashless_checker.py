"""
    Flashless checker serves the responsibility to check whether it is in flashless device

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
from .constant import MOUNTS_PATH, ROOTFS

logger = logging.getLogger(__name__)


def is_flashless() -> bool:
    """The checking on EMMc device is used to determine the flashless system.
    Flashless system doesn't have emmc device exists.

    @return True if flashless; otherwise, false
    """
    with open(MOUNTS_PATH, 'r') as file:
        return True if ROOTFS in file.read() else False
