"""
    FOTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
from pathlib import Path

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from .fota_error import FotaError
from ..constants import OTA_PACKAGE_CERT_PATH
from ..packagemanager.package_manager import verify_signature
from inbm_lib.xmlhandler import XmlException, XmlHandler
from ..dispatcher_callbacks import DispatcherCallbacks
from ..packagemanager.irepo import IRepo

from .bios_factory import BiosFactory


logger = logging.getLogger(__name__)


class Installer(ABC):
    """Base class for installing the new Firmware."""

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, repo: IRepo, xml_file: str, xml_schema: str) -> None:
        self._dispatcher_callbacks = dispatcher_callbacks
        self._repo: IRepo = repo
        logger.debug(f"_repo name is {self._repo.name()}")
        self._parsed_fota_conf = XmlHandler(xml=xml_file, is_file=True, schema_location=xml_schema)

    @abstractmethod
    def install(self, guid: Any, tool_options: Any, pkg_filename: str, signature: Optional[str],
                hash_algorithm: Optional[int], bios_vendor: str = None, platform_product: str = None) -> None:
        pass

    def get_product_params(self, platform_product: str) -> Dict:
        """This function returns the key value pairs of all the sub-elements for a given platform name
        from the firmware conf file.

        @param platform_product: Product platform name
        @return: Dict of sub elements associated with the platform name
        @raises FotaError: if there is an XmlException encountered. 
        """
        try:
            platforms = self._parsed_fota_conf.get_root_elements('firmware_product', 'name')
            logger.debug(f"Available Platforms: {platforms}")
            if platform_product not in platforms:
                raise FotaError(
                    f"The current platform is unsupported - {platform_product}")

            logger.debug(f"Platform information available: {platform_product}")

            params = self._parsed_fota_conf.get_children(
                f"firmware_product[@name='{platform_product}']")

            if not params:
                raise XmlException(
                    "The sub_element doesn't exist in the product configuration - product:{}, sub_element:{}".format(platform_product, 'bios_vendor'))
            try:
                is_guid_required = self._parsed_fota_conf.get_attribute(
                    f"firmware_product[@name='{platform_product}']", 'guid')
            except KeyError:
                is_guid_required = 'false'
            try:
                tool_opt_required = self._parsed_fota_conf.get_attribute(
                    f"firmware_product[@name='{platform_product}']", 'tool_options')
            except KeyError:
                tool_opt_required = 'false'

            tool_name = params.get('firmware_tool', None)

            if tool_name:
                if ' ' in tool_name or tool_name.isspace():
                    raise FotaError(f"FOTA tool name cannot contain spaces - {tool_name}")

            logger.debug(f"Guid required:{is_guid_required}")
            logger.debug(f"Tool options required:{tool_opt_required}")

            if is_guid_required == 'true':
                params['guid'] = is_guid_required

            if tool_opt_required == 'true':
                params['tool_options'] = tool_opt_required

            params['firmware_product'] = platform_product
            logger.debug(f"Product config: {params}")
            return params
        except XmlException as err:
            raise FotaError(f"Unable to fetch firmware product config information. {err}")

    def prepare_for_install(self,
                            pkg_filename: str,
                            checksum: Optional[str],
                            hash_algorithm: Optional[int]) -> None:
        """Method to verify if signature is provided, validate the signature and create a directory

        @param pkg_filename: filename of the package
        @param checksum: signed checksum in hex format of the package retrieved from manifest
        @param hash_algorithm: Crytographic Hash Algorithm i.e 256 or 384 or 512
        """
        logger.debug("")
        if os.path.exists(OTA_PACKAGE_CERT_PATH):
            if checksum and hash_algorithm:
                file_path = str(Path(str(self._repo.get_repo_path())) / pkg_filename)
                verify_signature(checksum, file_path,
                                 self._dispatcher_callbacks, hash_algorithm)
                self._dispatcher_callbacks.broker_core.telemetry('Attempting Firmware Update')
            else:
                logger.error("Signature required to proceed with OTA update.")
                raise FotaError(
                    "Device is provisioned with OTA package check certificate. Cannot proceed without signature.")
        else:
            no_signature_warning = 'WARNING: Device not provisioned for signature check.  Skipping signature check.'
            logger.warning(no_signature_warning)
            self._dispatcher_callbacks.broker_core.telemetry(no_signature_warning)


class LinuxInstaller(Installer):
    """Derived class. Installs new Firmware on a Linux OS.

    @param dispatcher_callbacks: callback to dispatcher
    @param repo: string representation of dispatcher's repository path
    @param xml_file: firmware xml file path
    @param xml_schema: firmware xml schema location
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, repo: IRepo, xml_file: str, xml_schema: str) -> None:
        super().__init__(dispatcher_callbacks, repo, xml_file, xml_schema)

    def install(self, guid: Any, tool_options: Any, pkg_filename: str, signature: Optional[str],
                hash_algorithm: Optional[int], bios_vendor: str = None, platform_product: str = None) -> None:
        """Performs a Linux FOTA install

        @param guid: system firmware type
        @param tool_options: tool options for firmware update
        @param pkg_filename: file name of OTA
        @param signature: signed checksum in hex format of the package retrieved from manifest
        @param hash_algorithm: hash algorithm of checksum i.e 256 or 384 or 512
        @param bios_vendor: bios vendor on the platform
        @param platform_product: platform product name
        @raises: FotaError
        """
        logger.debug(" ")

        super().prepare_for_install(pkg_filename=pkg_filename,
                                    checksum=signature,
                                    hash_algorithm=hash_algorithm)

        if platform_product is None:
            raise FotaError("Platform product unspecified.")

        params = super().get_product_params(platform_product)

        if params.get('tool_options', None):
            if not tool_options:
                raise FotaError("Tool options are mandatory for the platform's firmware update tool,"
                                " please check firmware documentation for the parameters.")
        else:
            if tool_options:
                raise FotaError(
                    "Tool options are not supported by the platform. Please check the firmware configuration.")

        factory = BiosFactory.get_factory(platform_product, params,
                                          self._dispatcher_callbacks, self._repo)
        factory.install(pkg_filename, self._repo.name(), tool_options, guid)


class WindowsInstaller(Installer):
    """Derived class. Installs new Firmware on a Windows OS.

    @param dispatcher_callbacks: callback to dispatcher
    @param repo: string representation of dispatcher's repository path
    @param xml_file: firmware xml file path
    @param xml_schema: firmware xml schema location
    """

    def __init__(self, dispatcher_callbacks: DispatcherCallbacks, repo: IRepo, xml_file: str, xml_schema: str) -> None:
        super().__init__(dispatcher_callbacks, repo, xml_file, xml_schema)

    def install(self, guid: Any, tool_options: Any, pkg_filename: str, signature: Optional[str],
                hash_algorithm: Optional[int], bios_vendor: str = None, platform_product: str = None) -> None:
        super().prepare_for_install(pkg_filename=pkg_filename,
                                    checksum=signature,
                                    hash_algorithm=hash_algorithm)
        if platform_product is None:
            raise FotaError("Platform product unspecified.")
        params = super().get_product_params(platform_product)
        factory = BiosFactory.get_factory(platform_product=platform_product,
                                          params=params,
                                          callback=self._dispatcher_callbacks,
                                          repo=self._repo)
        factory.install(pkg_filename, self._repo.name(), tool_options, guid)
