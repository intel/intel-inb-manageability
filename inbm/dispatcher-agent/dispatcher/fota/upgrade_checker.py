"""
    FOTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from abc import ABC, abstractmethod

from typing import Tuple, Dict
from datetime import datetime

from inbm_lib import wmi
from dispatcher.common import dispatcher_state
from inbm_lib.wmi_exception import WmiException
from .manifest import parse
from .fota_error import FotaError
from inbm_common_lib.device_tree import get_device_tree_system_info
from inbm_common_lib.dmi import is_dmi_path_exists, get_dmi_system_info, manufacturer_check
from inbm_common_lib.platform_info import PlatformInformation
from ..dispatcher_callbacks import DispatcherCallbacks

logger = logging.getLogger(__name__)


def check_upgrade_allowed(manifest_info: PlatformInformation,
                          platform_info: PlatformInformation,
                          dispatcher_callbacks: DispatcherCallbacks) -> None:
    """Check if manifest vendor name matches platform bios vendor and
    manifest release date is higher than bios release date

    @param manifest_info: Information parsed from manifest
    @param platform_info: Information retrieved from system
    @param dispatcher_callbacks: Dispatcher objects
    """
    logger.debug(" ")

    if isinstance(platform_info.bios_release_date, datetime) and isinstance(manifest_info.bios_release_date, datetime) \
            and manifest_info.bios_vendor == platform_info.bios_vendor \
            and manifest_info.bios_release_date > platform_info.bios_release_date:
        cf_message = f"""Current info: BiosVersion: {platform_info.bios_version},
                                      Bios Release Date: {platform_info.bios_release_date},
                                      Bios Vendor: {platform_info.bios_vendor},
                                      Platform Manufacturer: {platform_info.platform_mfg},
                                      Platform Product: {platform_info.platform_product}"""

        nf_message = f"""Capsule info: Bios Version: {manifest_info.bios_version},
                                      Bios Release Date: {manifest_info.bios_release_date},
                                      Bios Vendor: {manifest_info.bios_vendor},
                                      Platform Manufacturer: {manifest_info.platform_mfg},
                                      Platform Product: {manifest_info.platform_product}"""
        dispatcher_callbacks.broker_core.telemetry(cf_message)
        dispatcher_callbacks.broker_core.telemetry(nf_message)

        state = {'bios_version': platform_info.bios_version,
                 'release_date': platform_info.bios_release_date}
        dispatcher_state.write_dispatcher_state_to_state_file(state)
    elif manifest_info.bios_vendor == platform_info.bios_vendor \
            and manifest_info.bios_release_date == platform_info.bios_release_date:
        logger.debug("FOTA already applied")
        raise FotaError('Firmware Update Aborted as this package has already been applied.')
    else:
        logger.debug("Capsule rel. date < platform OR manifest vendor != platform vendor")
        dispatcher_callbacks.broker_core.telemetry(
            """Current Info: Bios Release Date: {}, Bios Version: {}, Bios Vendor: {}""".format(
                platform_info.bios_release_date, platform_info.bios_version, platform_info.bios_vendor))
        dispatcher_callbacks.broker_core.telemetry(
            f'Capsule Info: Bios Release Date: {manifest_info.bios_release_date}, '
            f'Bios Version: {manifest_info.bios_version}, Bios Vendor: {manifest_info.bios_vendor}')
        raise FotaError('Firmware Update Aborted: either capsule release date is lower than the one '
                        'on the platform or Manifest vendor name does not match the one on the platform')


class UpgradeChecker(ABC):
    """Base class for performing checks to see if the system is upgradable to the
    new Firmware.

    @param ota_element: resource portion of manifest
    @param dispatcher_callbacks: callback to dispatcher
    """

    def __init__(self, ota_element: Dict, dispatcher_callbacks: DispatcherCallbacks) -> None:
        self._dispatcher_callbacks = dispatcher_callbacks
        self._ota_element = ota_element

        self._platform_info = PlatformInformation()
        self._manifest_platform_info = PlatformInformation()

    @abstractmethod
    def check(self) -> Tuple[str, str]:
        pass

    def compare_product_and_manufacturer(self) -> None:
        if not (self._manifest_platform_info.platform_mfg == self._platform_info.platform_mfg
                and self._manifest_platform_info.platform_product == self._platform_info.platform_product):
            raise FotaError(
                'BIOS is not upgradable. Reason: Manufacturer and/or product name check failed')
        logger.debug("Manufacturer/Product check passed successfully")


class LinuxUpgradeChecker(UpgradeChecker):
    """Checks if the system is upgradable to the new Firmware on a Linux OS.

    @param ota_element: resource portion of manifest
    @param dispatcher_callbacks: callback to dispatcher
    """

    def __init__(self, ota_element, dispatcher_callbacks: DispatcherCallbacks):
        super().__init__(ota_element, dispatcher_callbacks)

    def check(self) -> Tuple[str, str]:
        """This method checks if dmi/device_tree information exist on the system.

        @return: bios vendor string, product string
        """
        logger.debug("")
        if is_dmi_path_exists(self._dispatcher_callbacks):
            self.check_with_dmi()
        else:
            self.check_with_device_tree()
        return self._platform_info.bios_vendor, self._platform_info.platform_product

    def check_with_dmi(self) -> None:
        """The method checks for current firmware vs the one in manifest file.
        It uses DMI path to get current BIOS details and matches with
        manifest file. It performs a range of validations for platform,
        version & release date checks.

        raises FotaError if encounters error when checking
        """
        logger.debug("Checking DMI BIOS information")
        try:
            self._platform_info = get_dmi_system_info()
        except ValueError as e:
            raise FotaError(
                f"BIOS is not upgradable. Reason: Error gathering BIOS information: {e}")

        logger.debug(f"BIOS details from DMI path: {self._platform_info}")

        if not self._platform_info:
            raise FotaError(
                "BIOS is not upgradable. Reason: Cannot get BIOS information from DMI path")

        self._manifest_platform_info = parse(self._ota_element)

        logger.debug(f"Parsed Manifest details: {self._manifest_platform_info}")

        if not manufacturer_check(
                self._manifest_platform_info.platform_mfg,
                self._platform_info.platform_mfg,
                self._manifest_platform_info.platform_product,
                self._platform_info.platform_product):
            raise FotaError(
                "BIOS is not upgradable. Reason: DMI manufacturer/product check failed")
        logger.debug("Manufacturer/product check passed successfully")

        if not manufacturer_check(
                self._manifest_platform_info.platform_mfg,
                self._platform_info.platform_mfg,
                self._manifest_platform_info.platform_product,
                self._platform_info.platform_product):
            raise FotaError(
                "BIOS is not upgradable. Reason: DMI manufacturer/product check failed")
        logger.debug("Manufacturer/product check parsed successfully")

        check_upgrade_allowed(self._manifest_platform_info,
                              self._platform_info,
                              dispatcher_callbacks=self._dispatcher_callbacks)

    def check_with_device_tree(self) -> None:
        """Uses device tree to retrieve the system information. This will be used if dmi path
        is not on the system.

        raises FotaError if encounters error when checking
        """
        logger.debug("Checking device_tree information")

        try:
            self._platform_info = get_device_tree_system_info()
        except ValueError as e:
            raise FotaError(
                f"BIOS is not upgradable. Reason: Error gathering BIOS information: {e}")
        logger.debug("Device-Tree parsed successfully")

        self._manifest_platform_info = parse(self._ota_element)
        logger.debug("Manifest parsed successfully")

        self.compare_product_and_manufacturer()

        check_upgrade_allowed(self._manifest_platform_info,
                              self._platform_info,
                              dispatcher_callbacks=self._dispatcher_callbacks)


class WindowsUpgradeChecker(UpgradeChecker):  # pragma: no cover
    """Performs checks to see if the system is upgradable to the
    new Firmware on a Windows OS.

    @param ota_element: resource portion of manifest
    @param dispatcher_callbacks: callback to dispatcher
    """

    def __init__(self, ota_element, dispatcher_callbacks):
        super().__init__(ota_element, dispatcher_callbacks)

    def check(self) -> Tuple[str, str]:
        """The method checks for current firmware vs the one in manifest file.
        It uses WMIC to get current BIOS details and matches with
        manifest file. It performs a range of validations for platform,
        version & release date checks.

        @return: bios vendor string, product string)
        @raises FotaError if encounters error when checking
        """

        logger.debug("")
        self.check_with_wmic()
        return self._platform_info.bios_vendor, self._platform_info.platform_product

    def check_with_wmic(self) -> None:
        """Uses WMIC to retrieve the system information."""

        logger.debug("Checking WMI information")
        platform_info = PlatformInformation()
        try:
            platform_info.bios_vendor = wmi.wmic_query('bios', 'manufacturer')['Manufacturer']
            platform_info.bios_version = wmi.wmic_query('bios', 'caption')['Caption']
            platform_info.bios_release_date = datetime.strptime(wmi.wmic_query(
                'bios', 'releasedate')['ReleaseDate'], '%Y%m%d000000.000000+000')
            platform_info.platform_mfg = wmi.wmic_query('csproduct', 'vendor')['Vendor']
            platform_info.platform_product = wmi.wmic_query('csproduct', 'name')['Name']
        except (KeyError, ValueError, WmiException):
            logger.debug("issue querying WMI during FOTA")
            raise FotaError("BIOS is not upgradable. Reason: Unable to query WMI BIOS information")

        self._manifest_platform_info = parse(self._ota_element)
        logger.debug("Manifest parsed successfully")

        self.compare_product_and_manufacturer()

        check_upgrade_allowed(self._manifest_platform_info,
                              self._platform_info,
                              dispatcher_callbacks=self._dispatcher_callbacks)
