""" Checks xlink device status and reports back if an error occurred.

    Copyright (C) 2020-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
from typing import List, Callable
from inbc.inbc_exception import InbcCode, InbcException
from inbc.xlink import Xlink
from inbc.constants import XLINK_STATUS_CHECKING_INTERVAL, DRIVER_NOT_FOUND
from inbm_vision_lib.timer import Timer
from inbm_vision_lib.constants import XLINK_DEV_OFF, XLINK_DEV_ERROR, XLINK_DEV_BUSY, XLINK_DEV_RECOVERY, \
    XLINK_DEV_READY

logger = logging.getLogger(__name__)


class XlinkChecker(object):
    """Class to check xlink device status

    @param stop_callback: callback for stop method
    """

    def __init__(self, stop_callback: Callable) -> None:
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
        self.running = True
        self.stop_callback: Callable = stop_callback
        self._device_list: List[Xlink] = []
        self.check_device_thread = Timer(
            XLINK_STATUS_CHECKING_INTERVAL, self._check_xlink_device_status, is_daemon=True)

        # Periodically checking xlink device status.
        self.check_device_thread.start()

    def stop(self) -> None:
        """Stop the xlink checker"""
        self.running = False
        self.check_device_thread.stop()

    def update_device_status(self, message) -> None:
        """Get the list of xlink device found.

        @param message: message received from vision-agent
        """
        msg = message.rsplit("-", 1)
        node_id = msg[0]
        status = int(msg[1].replace("\"", ""))

        if not self._is_device_exist(node_id):
            self._device_list.append(Xlink(node_id))

        for xlink_device in self._device_list:
            if xlink_device.device_id == node_id:
                xlink_device.update_device_status(status)

    def _check_xlink_device_status(self) -> None:
        """Periodically check xlink device status.
        If device status is not running recently, inbc will be stopped.

        """
        for xlink_device in self._device_list:
            if xlink_device.check_device_status() != XLINK_DEV_READY:
                self.return_error(xlink_device.check_device_status())
                self.stop_callback()
                break

        if self.running:
            self.check_device_thread = Timer(
                XLINK_STATUS_CHECKING_INTERVAL, self._check_xlink_device_status, is_daemon=True)
            self.check_device_thread.start()

    def _is_device_exist(self, node_id: str) -> bool:
        """ Check xlink device exist in the list.

            @param node_id: string representing node id
            @return: True if device exist. False if device not exist
        """
        for xlink_device in self._device_list:
            if xlink_device.device_id == node_id:
                return True
        return False

    def return_error(self, status: int) -> None:
        """ Check xlink device status and return corresponding error message

            @param status: xlink device status
        """
        if status == XLINK_DEV_OFF or status == DRIVER_NOT_FOUND:
            logger.error("No xlink device found.")
            logger.error("Please ensure xlink driver is installed. Command: lsmod | grep xlink.")
            logger.error("Please check dmesg to ensure there is no PCIe error. Command: dmesg")
            logger.error("Xlink Error {0}".format(InbcCode.XLINK_DEVICE_NOT_FOUND_OFF.value))
        elif status == XLINK_DEV_BUSY:
            logger.error("Device in busy stage. Stop at uboot?")
            logger.error("Xlink Error {0}".format(InbcCode.XLINK_DEVICE_BUSY.value))
        elif status == XLINK_DEV_RECOVERY:
            logger.error("Device in recovery mode.")
            logger.error("Xlink Error {0}".format(InbcCode.XLINK_DRIVER_UNAVAILABLE.value))
        else:
            logger.error("Xlink device error.")
            logger.error("Xlink Error {0}".format(InbcCode.XLINK_DRIVER_ERROR.value))
