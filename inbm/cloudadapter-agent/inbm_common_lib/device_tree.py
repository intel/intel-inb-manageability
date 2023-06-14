"""
    Use Linux device-tree path to gather system information.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from .constants import DEVICE_TREE_PATH, FW_DEVICE_TREE_PATH, DEVICE_TREE_MODEL, \
    BIOS_RELEASE_DATE, \
    BIOS_VERSION, \
    BIOS_VENDOR, SYSTEM_MANUFACTURER, SYSTEM_PRODUCT_NAME
from inbm_common_lib.constants import UNKNOWN, UNKNOWN_DATETIME
from inbm_common_lib.platform_info import PlatformInformation
import os
import logging
from datetime import datetime
from future import standard_library  # type: ignore
standard_library.install_aliases()


logger = logging.getLogger(__name__)


def get_device_tree_cpu_id() -> str:
    """Reads the CPU ID using Linux Device Tree

    @return: CPU ID of the platform.
    """
    return _read_file(DEVICE_TREE_PATH + DEVICE_TREE_MODEL, UNKNOWN)


def get_device_tree_system_info() -> PlatformInformation:
    """Reads the system information using Linux Device Tree

    @return: BIOS release date, BIOS vendor, BIOS version, Manufacturer, and Product
    of the platform.
    """
    bios_release_date = _parse_bios_date(
        _read_file(FW_DEVICE_TREE_PATH + BIOS_RELEASE_DATE, UNKNOWN))
    bios_vendor = _read_file(
        FW_DEVICE_TREE_PATH + BIOS_VENDOR, UNKNOWN)
    bios_version = _read_file(
        FW_DEVICE_TREE_PATH + BIOS_VERSION, UNKNOWN)
    platform_mfg = _read_file(
        FW_DEVICE_TREE_PATH + SYSTEM_MANUFACTURER, "")
    platform_product = _read_file(
        FW_DEVICE_TREE_PATH + SYSTEM_PRODUCT_NAME, "")
    return PlatformInformation(bios_release_date, bios_vendor, bios_version, platform_mfg, platform_product)


def _read_file(path: str, not_found_default: str) -> str:
    """Checks if the device tree path exists.  If it does, it will read the specified line in the
    path.

    @param path: device tree path
    @param not_found_default: default value to use if path is not found.
    @return: value associated with the specified path.
    """
    if not os.path.exists(path):
        logger.debug(
            "Checking device_tree.  File '%s' does not exist.", path)
        return not_found_default

    try:
        with open(path) as f:
            return f.readline().rstrip('\n').split('\x00')[0]
    except OSError as e:
        raise ValueError(f'Error {e} on reading the file {path}')


def is_device_tree_exists() -> bool:
    """The method verifies to see if device_tree path exists or not

    @return: returns false if there is no device_tree path otherwise true
    """
    if not os.path.isdir(DEVICE_TREE_PATH):
        logger.error("Device tree path does not exist")
        return False
    return True


def _parse_bios_date(unformatted_date: str) -> datetime:
    """Method to parse the string to retrieve date

    @param unformatted_date: date that needs to be parsed
    @return: Formatted date
    @raises: ValueError when format is not matched to the ones specified
    """
    for fmt in ["%b %d %Y %H:%M:%S"]:
        try:
            return datetime.strptime(unformatted_date, fmt)
        except ValueError:
            continue

    raise ValueError('Time date ' + str(unformatted_date) + ' does not match anything')
