"""
    FOTA update tool which is called from the dispatcher during installation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import platform
from threading import Timer
from typing import Any, Optional, Mapping

from future.moves.urllib.parse import urlparse
from inbm_common_lib.exceptions import UrlSecurityException
from inbm_common_lib.utility import canonicalize_uri
from inbm_common_lib.constants import REMOTE_SOURCE

from .constants import *
from .fota_error import FotaError
from .manifest import parse_tool_options, parse_guid, parse_hold_reboot_flag
from .os_factory import OsFactory, OsType
from ..common import dispatcher_state
from ..common.result_constants import *
from ..constants import UMASK_OTA
from ..dispatcher_callbacks import DispatcherCallbacks
from ..dispatcher_exception import DispatcherException
from ..downloader import download
from ..packagemanager.local_repo import DirectoryRepo

logger = logging.getLogger(__name__)


class FOTA:
    """AKA FOTA Tool
    An instance of this class will be called from the
    dispatcher if the requested type of update is FOTA
    """

    def __init__(self,
                 parsed_manifest: Mapping[str, Optional[Any]],
                 repo_type: str,
                 dispatcher_callbacks: DispatcherCallbacks) -> None:
        """Base class constructor for variable assignment, to send telemetry info and create a new
        directory if no repo is present

        @param parsed_manifest: Parsed parameters from manifest
        @param repo_type: OTA source location -> local or remote
        @param dispatcher_callbacks: DispatcherCallbacks instance
        """
        logger.debug(f"parsed_manifest: {parsed_manifest}")
        self._ota_element = parsed_manifest.get('resource')
        logger.debug(f"ota_element: {self._ota_element}")
        self._dispatcher_callbacks = dispatcher_callbacks
        self._uri: Optional[str] = parsed_manifest['uri']
        self._repo_type = repo_type

        repo_path: Optional[str]
        """If repo_type=local, then use path and not URI"""
        if self._repo_type == REMOTE_SOURCE:
            if not self._uri:
                raise FotaError("missing URI.")
            else:
                self._pkg_filename = os.path.basename(urlparse(self._uri).path)
                repo_path = None
        else:
            if self._ota_element is None or 'path' not in self._ota_element:
                raise FotaError('attempting to use local repo for FOTA but no path specified')
            self._pkg_filename = os.path.basename(self._ota_element['path'])
            path = self._ota_element.get('path', None)
            logger.debug(f"path: {path}")
            if path is None:
                repo_path = None
            else:
                repo_path = os.path.dirname(path)
            logger.debug(f"repo_path: {repo_path}")

        self.__signature = parsed_manifest['signature']
        self._hash_algorithm = parsed_manifest['hash_algorithm']

        self._username = parsed_manifest['username']
        self._password = parsed_manifest['password']
        if self._dispatcher_callbacks is None:
            raise FotaError("dispatcher_callbacks not specified in FOTA constructor")
        self._dispatcher_callbacks.broker_core.telemetry("Firmware Update Tool launched")
        if repo_path:
            logger.debug("Using manifest specified repo path")
            self._repo = DirectoryRepo(repo_path)
        else:
            logger.debug("Using default repo path")
            self._repo = DirectoryRepo(CACHE)

    def install(self) -> Result:
        """checks current platform versions and then issues download
        and install. Performs clean() in failure conditions
        @return: (Result) containing status code and message
        """
        logger.debug("")
        return_message: Result = Result()

        hold_reboot = False
        try:
            factory = OsFactory.get_factory(
                self._verify_os_supported(), self._ota_element, self._dispatcher_callbacks)

            bios_vendor, platform_product = factory.create_upgrade_checker().check()

            if self._repo_type.lower() == REMOTE_SOURCE:
                # need to perform this check here because some FOTA commands don't have a URI -- see constructor
                # (instead they have a path)
                if self._uri is None:
                    raise FotaError(
                        "internal error: _uri uninitialized in Fota.install with download requested in manifest")

                uri = canonicalize_uri(self._uri)
                download(dispatcher_callbacks=self._dispatcher_callbacks,
                         uri=uri,
                         repo=self._repo,
                         umask=UMASK_OTA,
                         username=self._username,
                         password=self._password)
            else:
                logger.debug("Skipping FOTA upgradable check for local repo")
            if self._ota_element is None:
                raise FotaError("missing ota_element")
            tool_options = parse_tool_options(self._ota_element)
            logger.debug(f"tool_options: {tool_options}")
            guid = parse_guid(self._ota_element)
            logger.debug(f"guid: {guid}")
            hold_reboot = parse_hold_reboot_flag(self._ota_element)
            logger.debug(f"holdReboot: {hold_reboot}; pkg_filename: {self._pkg_filename}")
            factory.create_installer(self._repo, FOTA_CONF_PATH, FOTA_CONF_SCHEMA_LOC).\
                install(guid=guid,
                        tool_options=tool_options,
                        pkg_filename=self._pkg_filename,
                        signature=self.__signature,
                        hash_algorithm=self._hash_algorithm,
                        bios_vendor=bios_vendor,
                        platform_product=platform_product)

            def trigger_reboot() -> None:
                """This method triggers a reboot."""
                factory.create_rebooter().reboot()
            if not hold_reboot:
                logger.debug("")
                state = {'restart_reason': "fota"}
                dispatcher_state.write_dispatcher_state_to_state_file(state)
                time_to_trigger_reboot = Timer(0.1, trigger_reboot)
                time_to_trigger_reboot.start()
                return_message = COMMAND_SUCCESS
            else:
                status = 'Reboot on hold after Firmware update...'
                state = {'restart_reason': "pota"}
                dispatcher_state.write_dispatcher_state_to_state_file(state)
                logger.debug(status)
                return_message = COMMAND_SUCCESS
                self._dispatcher_callbacks.broker_core.telemetry(status)
        except (DispatcherException, FotaError, UrlSecurityException, ValueError, FileNotFoundError) as e:
            error = 'Firmware Update Aborted: ' + str(e)
            logger.error(error)
            self._dispatcher_callbacks.broker_core.telemetry(error)
            return_message = INSTALL_FAILURE
            self._repo.delete(self._pkg_filename)
            # In POTA, mender file needs to be deleted also.
            if hold_reboot:
                self._repo.delete_all()
        finally:
            if return_message == COMMAND_SUCCESS:
                status = 'Firmware update in process...'
            else:
                status = 'Firmware Update Aborted'
                dispatcher_state.clear_dispatcher_state()
            logger.debug('Firmware update status: ' + status)
            self._dispatcher_callbacks.broker_core.telemetry(status)
            return return_message

    @staticmethod
    def _verify_os_supported():
        """checks if the current OS is supported.

        @return True if OS is supported; otherwise, false.
        @raise ValueError Unsupported OS
        """
        logger.debug("")
        os_type = platform.system()
        logger.debug(f"os_type: {os_type}")
        if os_type in OsType.__members__:
            return os_type
        else:
            logger.error("Unsupported OS type.")
            raise ValueError('Unsupported OS type.')

    def check(self) -> None:
        """validate the manifest before FOTA"""
        logger.debug("")
        factory = OsFactory.get_factory(
            self._verify_os_supported(), self._ota_element, self._dispatcher_callbacks)
        factory.create_upgrade_checker().check()
