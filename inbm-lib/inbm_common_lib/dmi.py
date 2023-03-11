"""
    Use Linux dmi path to gather system information.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import os
import logging

from typing import Optional, Any

from .platform_info import PlatformInformation
from .constants import *

logger = logging.getLogger(__name__)


def get_dmi_system_info() -> PlatformInformation:
    """Reads the system information from Linux Dmi path

    @return: BIOS release date, BIOS vendor, BIOS version, Manufacturer, Product
    of the platform
    """
    path = FW_DMI_IT_PATH if os.path.isdir(FW_DMI_IT_PATH) else FW_DMI_PATH

    bios_release_date = _parse_release_date(
        _read_file(path + DMI_BIOS_RELEASE_DATE, UNKNOWN))
    bios_vendor = _read_file(
        path + DMI_BIOS_VENDOR, UNKNOWN)
    bios_version = _read_file(
        path + DMI_BIOS_VERSION, UNKNOWN)
    platform_mfg = _read_file(
        path + DMI_SYSTEM_MANUFACTURER, "")
    platform_product = _read_file(
        path + DMI_SYSTEM_PRODUCT_NAME, "")

    if UNKNOWN in [bios_vendor, bios_version, bios_release_date]:
        logger.debug(
            "return_value: bios_vendor:{}, bios_version:{},"
            " bios_release_date:{}, platform_mfg: {}, platform_product:{}". format(
                bios_vendor,
                bios_version,
                bios_release_date,
                platform_mfg,
                platform_product))
        return PlatformInformation()
    return PlatformInformation(bios_release_date, bios_vendor,
                               bios_version, platform_mfg, platform_product)


def _read_file(path: str, not_found_default: str) -> str:
    """Checks if the DMI path exists.  If it does, it will read the specified line in the
    path.

    @param path: DMI path
    @param not_found_default: default value to use if path is not found.
    @return: value associated with the specified path.
    """
    logger.debug(f"path: {path}")
    if not os.path.exists(path):
        logger.error(
            "Checking DMI.  File '%s' does not exist.", path)
        return not_found_default

    try:
        with open(path) as f:
            return f.readline().rstrip('\n').split('\x00')[0]
    except OSError as e:
        raise ValueError(f'Error {e} on reading the file {path}')


def is_dmi_path_exists(dispatcher_callbacks: Optional[Any] = None) -> bool:
    """The method verifies to see if DMI path exists or not

    @return: returns false if there is no dmi path otherwise true
    """
    if not os.path.isdir(DMI_PATH):
        logger.error("DMI path does not exist")
        if dispatcher_callbacks:
            dispatcher_callbacks.broker_core.telemetry(
                "DMI path {} does not exist". format(DMI_PATH))
        return False
    return True


def _parse_release_date(unformatted_date: str) -> datetime:
    """Method to parse the string to retrieve the date

    @param unformatted_date: date that needs to be parsed
    @return: Formatted date
    @raises: ValueError when format is not matched to the ones specified
    """
    for fmt in ("%m/%d/%Y", "%b %d %Y"):
        try:
            return datetime.strptime(unformatted_date, fmt)
        except ValueError:
            continue
    raise ValueError('Time date does not match anything')


def manufacturer_check(
        manifest_mfg: str,
        platform_mfg: str,
        manifest_mfg_product: str,
        platform_product: str) -> bool:
    """Helper function for check_current_version which performs a comparison of manufacturer
    information

    @param manifest_mfg: manufacturer's name from manifest file
    @param platform_mfg: manufacturer's name from platform
    @param manifest_mfg_product: manufacturer's product from manifest file
    @param platform_product: manufacturer's product from platform
    @return True if manufacturer information matches; otherwise, false.
    """
    logger.debug("")
    if platform_mfg == 'To be filled by O.E.M.' or not platform_mfg:
        platform_mfg = ''
    if platform_product == 'To be filled by O.E.M.' or not platform_product:
        platform_product = ''
    logger.debug(
        "manifest_mfg: {}, platform_mfg: {}, manifest_mfg_product: {},"
        " platform_product: {}".format(
            manifest_mfg,
            platform_mfg,
            manifest_mfg_product,
            platform_product))
    return manifest_mfg == platform_mfg and manifest_mfg_product == platform_product
