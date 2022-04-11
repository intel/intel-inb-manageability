"""
    Initialize and call the Xlink library

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from typing import List
from .ixlink_wrapper import X_LINK_SUCCESS, xlink_handle, HOST_DEVICE
from ..constants import XLINK_LIB_PATH, SW_DEVICE_ID_PCIE_INTERFACE, SW_DEVICE_ID_MEDIA_FUNCTION, \
    SW_DEVICE_ID_INTERFACE_SHIFT, SW_DEVICE_ID_INTERFACE_MASK, XLINK_SW_DEV_ID_PCIE_FUNCTION_MASK, \
    MAXIMUM_DEVICE_NAME_SIZE
from inbm_vision_lib.path_prefixes import IS_WINDOWS

from ctypes import *

logger = logging.getLogger(__name__)


class XLinkLibrary(object):
    def __init__(self) -> None:
        self._xlink_library = CDLL(XLINK_LIB_PATH)
        self._xlink_library.xlink_initialize()

    def get_all_xlink_pcie_device_ids(self) -> List[int]:
        """ Call xlink API to get all xlink PCIe device.

            @return: list that contains xlink PCIe device id
        """
        dev_id_list = (c_int * 64)()
        xlink_pcie_dev_ids = []
        num_devices = 0 if not IS_WINDOWS else 64
        num_dev = c_int(num_devices)
        logger.debug('Call xlink get device list...')
        status = self._xlink_library.xlink_get_device_list(
            byref(dev_id_list), byref(num_dev))
        if status is not X_LINK_SUCCESS:
            logger.error('xlink_get_device_list failed - %s', str(status))
        logger.debug(f"number of dev = {num_dev.value}, device list: ")
        for num in range(len(dev_id_list)):
            logger.debug("dev_id_list[{}]: {}".format(num, dev_id_list[num]))
            interface = _get_interface_from_sw_device_id(dev_id_list[num])
            if interface == SW_DEVICE_ID_PCIE_INTERFACE and SW_DEVICE_ID_MEDIA_FUNCTION:
                xlink_pcie_dev_ids.append(dev_id_list[num])
                logger.debug("dev {} with dev id {} is added".format(num, dev_id_list[num]))
            if interface == SW_DEVICE_ID_PCIE_INTERFACE:
                xlink_pcie_dev_ids.append(dev_id_list[num])
                logger.debug("dev {} with dev id {} is added".format(num, dev_id_list[num]))
        return xlink_pcie_dev_ids

    def filter_first_slice_from_list(self, xlink_pcie_dev_list: List[int]) -> List[int]:
        """ Filter the device list. Only retain root PCIe device.
            The PCIe id can be obtained using xlink_get_device_name API.
            In TBH, only root xlink PCIe device from TBH will be connected.
            E.g. List[04:00.0, 04:00.2, 04:00.4] -> List[04:00.0]

            @param xlink_pcie_dev_list: list of xlink sw device id
            @return: filtered list that only contains root PCIe device
        """
        dev_list = xlink_pcie_dev_list.copy()
        for dev_id in dev_list:
            dev_name = self._get_device_name(dev_id)
            if dev_name.split('.', 1)[1] != "0":
                xlink_pcie_dev_list.remove(dev_id)
        return xlink_pcie_dev_list

    def _get_device_name(self, sw_device_id: int) -> str:
        """ Call xlink API to get device's name based on sw device id

            @param sw_device_id: xlink sw device id to be checked
            @return: string representing pcie id. Example: 04:00.0
        """
        xlink_handler = xlink_handle(dev_type=HOST_DEVICE)
        xlink_handler.sw_device_id = sw_device_id
        dev_name_p = create_string_buffer(MAXIMUM_DEVICE_NAME_SIZE)
        size = c_uint(MAXIMUM_DEVICE_NAME_SIZE)
        status = self._xlink_library.xlink_get_device_name(byref(xlink_handler), byref(dev_name_p), size)
        if status is not X_LINK_SUCCESS:
            print('xlink_get_device_name failed - %s', str(status))

        dev_name = ''
        try:
            for i in range(size.value):
                dev_name = dev_name + dev_name_p[i].decode('utf-8')  # type: ignore
        except UnicodeDecodeError:
            pass

        return dev_name.split('\x00')[0]


def _get_interface_from_sw_device_id(sw_device_id: int) -> int:
    """ Gets the Xlink interface type

        @param sw_device_id: xlink sw device id to be checked
        @return: number representing xlink interface type
    """
    return (sw_device_id >> SW_DEVICE_ID_INTERFACE_SHIFT) & SW_DEVICE_ID_INTERFACE_MASK


def _get_pcie_function(sw_device_id: int) -> int:
    """Get the Xlink PCIe Function for TBH.
    Services such as manageability should use the media function.  0x1 or 0x3

    @param sw_device_id: xlink sw device id to be checked
    @return: number representing xlink PCIe function type
    """
    return sw_device_id & XLINK_SW_DEV_ID_PCIE_FUNCTION_MASK
