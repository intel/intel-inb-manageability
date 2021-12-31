"""
    A xlink struct to store the xlink object information.

    Copyright (C) 2020-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import List
from inbm_vision_lib.constants import XLINK_DEV_READY
from inbc.constants import MAX_STATUS_NUM


class Xlink(object):
    """Xlink object information.

    @param device_id: xlink sw device id
    """

    def __init__(self, device_id) -> None:
        self.device_id = device_id
        self.device_status: List[int] = []

    def update_device_status(self, status: int) -> None:
        """Update xlink device status. It will store thirty of the latest status.

        @param status: xlink device status
        """
        self.device_status.append(status)
        if len(self.device_status) > MAX_STATUS_NUM:
            self.device_status.pop(0)

    def check_device_status(self) -> int:
        """Return recent status of xlink device.

        @return: xlink device status
        """
        if len(self.device_status) >= MAX_STATUS_NUM and self.device_status.count(self.device_status[0]) >= len(
                self.device_status):
            return self.device_status[0]
        else:
            return XLINK_DEV_READY

    def get_device_id(self) -> int:
        """Return xlink sw device id

        @return: xlink sw device id
        """
        return self.device_id
