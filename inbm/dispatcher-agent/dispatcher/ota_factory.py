"""
    OTA abstract factory which is used to execute OTA calls from the cloud.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import abc
import logging
from typing import Any, Optional, Mapping

from .config_dbs import ConfigDbs
from .constants import OtaType
from .dispatcher_callbacks import DispatcherCallbacks
from .ota_parser import AotaParser
from .ota_parser import FotaParser
from .ota_parser import OtaParser
from .ota_parser import PotaParser
from .ota_parser import SotaParser
from .ota_thread import AotaThread
from .ota_thread import FotaThread
from .ota_thread import OtaThread
from .ota_thread import SotaThread
from .install_check_service import InstallCheckService
from .update_logger import UpdateLogger
from .dispatcher_broker import DispatcherBroker

logger = logging.getLogger(__name__)


class OtaFactory(metaclass=abc.ABCMeta):
    """Abstract Factory for creating the concrete classes based on the OTA request type

    @param dispatcher_callbacks: Callbacks in Dispatcher object   
    """

    def __init__(self,
                 repo_type: str,
                 dispatcher_callbacks: DispatcherCallbacks,
                 install_check_service: InstallCheckService) -> None:
        self._dispatcher_callbacks = dispatcher_callbacks
        self._install_check_service = install_check_service
        self._repo_type = repo_type

    @abc.abstractmethod
    def create_parser(self) -> OtaParser:
        pass

    @abc.abstractmethod
    def create_thread(self, parsed_manifest: Mapping[str, Optional[Any]]) -> OtaThread:
        pass

    @staticmethod
    def get_factory(ota_type,
                    repo_type: Any,
                    dispatcher_callbacks: DispatcherCallbacks,
                    broker_core: DispatcherBroker,
                    proceed_without_rollback: bool,
                    sota_repos: Optional[str],
                    install_check_service: InstallCheckService,
                    update_logger: UpdateLogger,
                    dbs: ConfigDbs) -> Any:
        """Create an OTA factory of a specified OTA type

        @param ota_type: The OTA type
        @param repo_type: OTA source location -> local or remote
        @param dispatcher_callbacks: reference to a DispatcherCallbacks object        
        @param broker_core: MQTT broker to other INBM services
        @param proceed_without_rollback: Is it OK to run SOTA without rollback ability?
        @param sota_repos: new Ubuntu/Debian mirror (or None)
        @param install_check_service: provides install_check
        @param update_logger: UpdateLogger (expected to update after OTA) 
        @param dbs: ConfigDbs.ON or ConfigDbs.WARN or ConfigDbs.OFF
        @raise ValueError: Unsupported OTA type
        """

        logger.debug(f"ota_type: {ota_type}")
        if ota_type == OtaType.FOTA.name:
            return FotaFactory(repo_type, dispatcher_callbacks, broker_core, install_check_service, update_logger)
        if ota_type == OtaType.SOTA.name:
            return SotaFactory(repo_type, dispatcher_callbacks, broker_core, proceed_without_rollback,
                               sota_repos, install_check_service, update_logger)
        if ota_type == OtaType.AOTA.name:
            return AotaFactory(repo_type, dispatcher_callbacks, broker_core, install_check_service, update_logger, dbs=dbs)
        if ota_type == OtaType.POTA.name:
            return PotaFactory(repo_type, dispatcher_callbacks, install_check_service)
        raise ValueError('Unsupported OTA type: {}'.format(str(ota_type)))


class FotaFactory(OtaFactory):
    """FOTA concrete class

    @param dispatcher_callbacks: Callbacks in Dispatcher object
    @param broker_core: MQTT broker to other INBM services
    @param install_check_service: provides install_check
    @param update_logger: UpdateLogger instance (expected to update after OTA)
    """

    def __init__(self,
                 repo_type: str,
                 dispatcher_callbacks: DispatcherCallbacks,
                 broker_core: DispatcherBroker,
                 install_check_service: InstallCheckService,
                 update_logger: UpdateLogger) -> None:

        super().__init__(repo_type, dispatcher_callbacks, install_check_service)
        self._update_logger = update_logger
        self._broker_core = broker_core

    def create_parser(self) -> OtaParser:
        logger.debug(" ")
        return FotaParser(self._repo_type, self._dispatcher_callbacks)

    def create_thread(self, parsed_manifest: Mapping[str, Optional[Any]]) -> OtaThread:
        logger.debug(" ")
        return FotaThread(self._repo_type, self._dispatcher_callbacks, self._broker_core,
                          self._install_check_service, parsed_manifest,
                          update_logger=self._update_logger)


class SotaFactory(OtaFactory):
    """SOTA concrete class

    @param dispatcher_callbacks: Callbacks in Dispatcher object
    @param broker_core: MQTT broker to other INBM services
    @param proceed_without_rollback: Is it OK to run SOTA without rollback ability?
    @param install_check_service: provides InstallCheckService
    @param sota_repos: new Ubuntu/Debian mirror (or None)
    @param update_logger: UpdateLogger (expected to update after OTA) 
    """

    def __init__(self,
                 repo_type: str,
                 dispatcher_callbacks: DispatcherCallbacks,
                 broker_core: DispatcherBroker,
                 proceed_without_rollback: bool,
                 sota_repos: Optional[str],
                 install_check_service: InstallCheckService,
                 update_logger: UpdateLogger) -> None:

        super().__init__(repo_type, dispatcher_callbacks, install_check_service)
        self._sota_repos = sota_repos
        self._proceed_without_rollback = proceed_without_rollback
        self._update_logger = update_logger
        self._broker_core = broker_core

    def create_parser(self) -> OtaParser:
        logger.debug(" ")
        return SotaParser(self._repo_type, self._dispatcher_callbacks)

    def create_thread(self, parsed_manifest: Mapping[str, Optional[Any]]) -> OtaThread:
        logger.debug(" ")
        return SotaThread(self._repo_type,
                          self._dispatcher_callbacks,
                          self._broker_core,
                          self._proceed_without_rollback,
                          self._sota_repos,
                          self._install_check_service,
                          parsed_manifest,
                          self._update_logger)


class AotaFactory(OtaFactory):
    """AOTA concrete class

    @param dispatcher_callbacks: Callbacks in Dispatcher object
    @param broker_core: MQTT broker to other INBM services
    @param install_check_service: provides install_check
    @param update_logger: UpdateLogger (expected to update after OTA) 
    @param dbs: ConfigDbs.{ON, OFF, WARN}
    """

    def __init__(self,
                 repo_type: str,
                 dispatcher_callbacks: DispatcherCallbacks,
                 broker_core: DispatcherBroker,
                 install_check_service: InstallCheckService,
                 update_logger: UpdateLogger,
                 dbs: ConfigDbs) -> None:

        super().__init__(repo_type, dispatcher_callbacks, install_check_service)
        self._dbs = dbs
        self._update_logger = update_logger
        self._broker_core = broker_core

    def create_parser(self) -> OtaParser:
        logger.debug(" ")
        return AotaParser(self._repo_type, self._dispatcher_callbacks)

    def create_thread(self, parsed_manifest: Mapping[str, Optional[Any]]) -> OtaThread:
        logger.debug(" ")
        return AotaThread(self._repo_type,
                          self._dispatcher_callbacks,
                          self._broker_core,
                          self._update_logger,
                          self._install_check_service,
                          parsed_manifest,
                          self._dbs)


class PotaFactory(OtaFactory):
    """POTA concrete class

    @param dispatcher_callbacks: Callbacks in Dispatcher object
    @param install_check_service: provides install_check
    """

    def __init__(self,
                 repo_type: str,
                 dispatcher_callbacks: DispatcherCallbacks,
                 install_check_service: InstallCheckService) -> None:

        super().__init__(repo_type, dispatcher_callbacks, install_check_service)

    def create_parser(self) -> OtaParser:
        logger.debug(" ")
        return PotaParser(self._repo_type, self._dispatcher_callbacks)

    def create_thread(self, parsed_manifest: Mapping[str, Optional[Any]]):
        logger.debug(" ")
        pass
