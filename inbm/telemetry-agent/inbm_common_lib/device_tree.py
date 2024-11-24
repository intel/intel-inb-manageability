"""
    Use Linux device-tree path to gather system information.

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from inbm_common_lib.constants import UNKNOWN, UNKNOWN_DATETIME
from inbm_common_lib.platform_info import PlatformInformation
import os
import logging
from datetime import datetime


# Device tree base paths
DEVICE_TREE_PATH = '/proc/device-tree/'
FW_DEVICE_TREE_PATH = '/proc/device-tree/firmware/bios/'

# Lookup table for device tree paths
DEVICE_TREE_PATHS = {
    'model': DEVICE_TREE_PATH + 'model',
    'bios_release_date': FW_DEVICE_TREE_PATH + 'bios-release-date',
    'bios_vendor': FW_DEVICE_TREE_PATH + 'bios-vendor',
    'bios_version': FW_DEVICE_TREE_PATH + 'bios-version',
    'system_manufacturer': FW_DEVICE_TREE_PATH + 'system-manufacturer',
    'system_product_name': FW_DEVICE_TREE_PATH + 'system-product-name'
}

logger = logging.getLogger(__name__)


def get_device_tree_cpu_id() -> str:
    """Reads the CPU ID using Linux Device Tree

    @return: CPU ID of the platform.
    """
    return _read_file(DEVICE_TREE_PATHS['model'], UNKNOWN)


def get_device_tree_system_info() -> PlatformInformation:
    """Reads the system information using Linux Device Tree

    @return: BIOS release date, BIOS vendor, BIOS version, Manufacturer, and Product
    of the platform.
    """
    bios_release_date = _parse_bios_date(
        _read_file(DEVICE_TREE_PATHS['bios_release_date'], UNKNOWN))
    bios_vendor = _read_file(
        DEVICE_TREE_PATHS['bios_vendor'], UNKNOWN)
    bios_version = _read_file(
        DEVICE_TREE_PATHS['bios_version'], UNKNOWN)
    platform_mfg = _read_file(
        DEVICE_TREE_PATHS['system_manufacturer'], "")
    platform_product = _read_file(
        DEVICE_TREE_PATHS['system_product_name'], "")
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
    """The method verifies to see if all device_tree paths exist or not

    @return: returns false if any path does not exist, otherwise true
    """
    for path in DEVICE_TREE_PATHS.values():
        if not os.path.exists(path):
            logger.error("Device tree path '%s' does not exist", path)
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