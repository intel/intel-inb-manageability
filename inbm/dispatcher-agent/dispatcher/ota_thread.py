"""
    Starts OTA thread.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import abc
import logging
import os
from threading import Lock
from typing import Optional, Any, Mapping

from inbm_lib.constants import TRTL_PATH
from inbm_common_lib.exceptions import UrlSecurityException

from .aota import aota
from .aota.aota_error import AotaError
from .common.result_constants import (
    Result,
    OTA_FAILURE,
    COMMAND_SUCCESS,
    OTA_FAILURE_IN_PROGRESS)
from .config_dbs import ConfigDbs
from .dispatcher_exception import DispatcherException
from .dispatcher_callbacks import DispatcherCallbacks
from .fota.fota import FOTA
from .fota.fota_error import FotaError
from .sota.sota import SOTA
from .sota.sota_error import SotaError

logger = logging.getLogger(__name__)
ota_lock = Lock()


class OtaThread(metaclass=abc.ABCMeta):
    """Base class for starting OTA thread.

    @param repo_type: source location -> local or remote
    @param dispatcher_callbacks: callback to Dispatcher object
    @param parsed_manifest: parameters from OTA manifest
    """

    def __init__(self,
                 repo_type: str,
                 dispatcher_callbacks: DispatcherCallbacks,
                 parsed_manifest: Mapping[str, Optional[Any]]) -> None:

        self._repo_type = repo_type
        self._dispatcher_callbacks = dispatcher_callbacks
        self._parsed_manifest = parsed_manifest

    def start(self):
        logger.debug('Performing pre install check')
        try:
            self._dispatcher_callbacks.install_check()
            logger.info('Manifest has been parsed successfully')
        except DispatcherException:
            raise DispatcherException('Pre OTA check failed')

    def post_install_check(self) -> None:
        logger.debug('Performing post install check')
        self._dispatcher_callbacks.install_check()

    def check(self) -> None:
        pass


class FotaThread(OtaThread):
    """Performs thread synchronization, FOTA and returns the result.

    @param repo_type: source location -> local or remote
    @param dispatcher_callbacks: reference to the main Dispatcher object
    @param parsed_manifest: parameters from OTA manifest
    """

    def __init__(self, repo_type: str, dispatcher_callbacks: DispatcherCallbacks,
                 parsed_manifest: Mapping[str, Optional[Any]]) -> None:
        super().__init__(repo_type, dispatcher_callbacks, parsed_manifest)

    def start(self) -> Result:  # pragma: no cover
        """Starts the FOTA thread and which checks for existing locks before delegating to
        an OTA specific method

        @return (dict): result of the OTA
        """
        logger.debug(" ")
        super().start()

        global ota_lock
        if ota_lock.acquire(False):
            try:
                fota_instance = FOTA(parsed_manifest=self._parsed_manifest, repo_type=self._repo_type,
                                     dispatcher_callbacks=self._dispatcher_callbacks)
                return fota_instance.install()
            except FotaError as e:
                self._dispatcher_callbacks.broker_core.telemetry(
                    "Error during FOTA: " + str(e))
                return OTA_FAILURE
            finally:
                ota_lock.release()
        else:
            self._dispatcher_callbacks.broker_core.telemetry(
                "Another OTA in progress, Try Later")
            return OTA_FAILURE_IN_PROGRESS

    def check(self) -> None:
        """ Perform FOTA manifest checking"""
        try:
            fota_instance = FOTA(parsed_manifest=self._parsed_manifest, repo_type=self._repo_type,
                                 dispatcher_callbacks=self._dispatcher_callbacks)
            fota_instance.check()
        except FotaError as e:
            self._dispatcher_callbacks.broker_core.telemetry(
                "Error during FOTA: " + str(e))
            raise FotaError(str(e))


class SotaThread(OtaThread):
    """"Performs thread synchronization, SOTA and returns the result.

    @param repo_type: source location -> local or remote
    @param dispatcher_callbacks callback to the main Dispatcher object
    @param parsed_manifest: parameters from OTA manifest
    @return (dict): dict representation of COMMAND_SUCCESS or OTA_FAILURE/OTA_FAILURE_IN_PROGRESS
    """

    def __init__(self, repo_type: str, dispatcher_callbacks: DispatcherCallbacks,
                 parsed_manifest: Mapping[str, Optional[Any]]) -> None:
        super().__init__(repo_type, dispatcher_callbacks, parsed_manifest)

    def start(self) -> Result:  # pragma: no cover
        """Starts the SOTA thread and which checks for existing locks before delegating to
        an OTA specific method

        @return (dict): result of the OTA
        """
        logger.debug(" ")
        super().start()

        global ota_lock
        if ota_lock.acquire(False):
            try:
                sota_instance = SOTA(parsed_manifest=self._parsed_manifest,
                                     repo_type=self._repo_type,
                                     dispatcher_callbacks=self._dispatcher_callbacks)
                try:
                    sota_instance.execute(self._dispatcher_callbacks.proceed_without_rollback)
                    return COMMAND_SUCCESS
                except SotaError as e:
                    self._dispatcher_callbacks.broker_core.telemetry(
                        "Error executing SOTA: " + str(e))
                    return OTA_FAILURE
            finally:
                ota_lock.release()
        else:
            self._dispatcher_callbacks.broker_core.telemetry(
                "Another OTA in progress, Try Later")
            return OTA_FAILURE_IN_PROGRESS

    def check(self) -> None:
        """ Perform SOTA manifest checking"""
        try:
            sota_instance = SOTA(parsed_manifest=self._parsed_manifest,
                                 repo_type=self._repo_type,
                                 dispatcher_callbacks=self._dispatcher_callbacks)
            sota_instance.check()
        except SotaError as e:
            self._dispatcher_callbacks.broker_core.telemetry(
                "Error executing SOTA: " + str(e))
            raise SotaError(str(e))


class AotaThread(OtaThread):
    """"Performs thread synchronization, AOTA and returns the result.

    @param repo_type: source location -> local or remote
    @param dispatcher_callbacks: reference to the main Dispatcher object
    @param parsed_manifest: parameters from OTA manifest
    @param dbs: ConfigDbs.ON, ConfigDbs.OFF, or ConfigDbs.WARN
    @return (dict): dict representation of INSTALL_SUCCESS or INSTALL_FAILURE
    """

    def __init__(self,
                 repo_type: str,
                 dispatcher_callbacks: DispatcherCallbacks,
                 parsed_manifest: Mapping[str, Optional[Any]],
                 dbs: ConfigDbs) -> None:
        super().__init__(repo_type, dispatcher_callbacks, parsed_manifest)
        self._dbs = dbs

    def _check_trtl_binary(self) -> None:
        if not os.path.isfile(TRTL_PATH):
            raise AotaError(
                "Trtl binary missing. Cannot proceed with the AOTA update...")

    def start(self) -> Result:  # pragma: no cover
        """Starts the AOTA thread and which checks for existing locks before delegating to
        an OTA specific method

        @return (dict): result of the OTA
        """
        logger.debug(" ")
        super().start()

        global ota_lock
        if ota_lock.acquire(False):
            try:
                self._check_trtl_binary()
                # Passing dispatcher instance to AOTA and spawn a thread for AOTA
                aota.AOTA(dispatcher_callbacks=self._dispatcher_callbacks,
                          parsed_manifest=self._parsed_manifest,
                          dbs=self._dbs).run()
                return COMMAND_SUCCESS
            except (AotaError, UrlSecurityException) as e:
                self._dispatcher_callbacks.broker_core.telemetry(str(e))
                logger.error('Error during install: %s', str(e))
                raise AotaError(str(e))
            finally:
                ota_lock.release()
        else:
            self._dispatcher_callbacks.broker_core.telemetry(
                "Another OTA in progress, Try Later")
            return OTA_FAILURE_IN_PROGRESS
