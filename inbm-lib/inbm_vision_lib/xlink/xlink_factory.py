"""
    Factory method to create the concrete wrapper class

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import Callable, Optional
from .ixlink_wrapper import IXlinkWrapper
from .xlink_wrapper import XlinkWrapper
from .xlink_secure_wrapper import XlinkSecureWrapper
from .xlink_windows_wrapper import XlinkWindowsWrapper
from ..path_prefixes import IS_WINDOWS


def xlink_wrapper_factory(is_secure: bool, callback: Callable, channel_id: int, node_xlink_dev_id: int,
                          is_boot_device: bool, async_cb: Optional[Callable]) -> IXlinkWrapper:
    return XlinkSecureWrapper(callback, channel_id, node_xlink_dev_id, is_boot_device) \
        if is_secure else XlinkWindowsWrapper(callback, channel_id, node_xlink_dev_id, is_boot_device) \
        if IS_WINDOWS else XlinkWrapper(callback, channel_id, node_xlink_dev_id, is_boot_device, async_cb)
