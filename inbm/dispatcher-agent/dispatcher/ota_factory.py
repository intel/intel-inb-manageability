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

logger = logging.getLogger(__name__)


class OtaFactory(metaclass=abc.ABCMeta):
    """Abstract Factory for creating the concrete classes based on the OTA request type

    @param dispatcher_callbacks: Callbacks in Dispatcher object
    """

    def __init__(self, repo_type: str, dispatcher_callbacks: DispatcherCallbacks) -> None:
        self._dispatcher_callbacks = dispatcher_callbacks
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
                    dbs: ConfigDbs) -> Any:
        """Create an OTA factory of a specified OTA type

        @param ota_type: The OTA type
        @param repo_type: OTA source location -> local or remote
        @param dispatcher_callbacks: reference to a DispatcherCallbacks object
        @param dbs: ConfigDbs.ON or ConfigDbs.WARN or ConfigDbs.OFF
        @raise ValueError: Unsupported OTA type
        """

        logger.debug(f"ota_type: {ota_type}")
        if ota_type == OtaType.FOTA.name:
            return FotaFactory(repo_type, dispatcher_callbacks)
        if ota_type == OtaType.SOTA.name:
            return SotaFactory(repo_type, dispatcher_callbacks)
        if ota_type == OtaType.AOTA.name:
            return AotaFactory(repo_type, dispatcher_callbacks, dbs=dbs)
        if ota_type == OtaType.POTA.name:
            return PotaFactory(repo_type, dispatcher_callbacks)
        raise ValueError('Unsupported OTA type: {}'.format(str(ota_type)))


class FotaFactory(OtaFactory):
    """FOTA concrete class

    @param dispatcher_callbacks: Callbacks in Dispatcher object
    """

    def __init__(self, repo_type: str, dispatcher_callbacks: DispatcherCallbacks) -> None:
        super().__init__(repo_type, dispatcher_callbacks)

    def create_parser(self) -> OtaParser:
        logger.debug(" ")
        return FotaParser(self._repo_type, self._dispatcher_callbacks)

    def create_thread(self, parsed_manifest: Mapping[str, Optional[Any]]) -> OtaThread:
        logger.debug(" ")
        return FotaThread(self._repo_type, self._dispatcher_callbacks, parsed_manifest)


class SotaFactory(OtaFactory):
    """SOTA concrete class

    @param dispatcher_callbacks: Callbacks in Dispatcher object
    """

    def __init__(self, repo_type: str, dispatcher_callbacks: DispatcherCallbacks) -> None:
        super().__init__(repo_type, dispatcher_callbacks)

    def create_parser(self) -> OtaParser:
        logger.debug(" ")
        return SotaParser(self._repo_type, self._dispatcher_callbacks)

    def create_thread(self, parsed_manifest: Mapping[str, Optional[Any]]) -> OtaThread:
        logger.debug(" ")
        return SotaThread(self._repo_type, self._dispatcher_callbacks, parsed_manifest)


class AotaFactory(OtaFactory):
    """AOTA concrete class

    @param dispatcher_callbacks: Callbacks in Dispatcher object
    @param dbs: ConfigDbs.{ON, OFF, WARN}
    """

    def __init__(self, repo_type: str, dispatcher_callbacks: DispatcherCallbacks, dbs: ConfigDbs) -> None:

        super().__init__(repo_type, dispatcher_callbacks)
        self._dbs = dbs

    def create_parser(self) -> OtaParser:
        logger.debug(" ")
        return AotaParser(self._repo_type, self._dispatcher_callbacks)

    def create_thread(self, parsed_manifest: Mapping[str, Optional[Any]]) -> OtaThread:
        logger.debug(" ")
        return AotaThread(self._repo_type, self._dispatcher_callbacks, parsed_manifest, self._dbs)


class PotaFactory(OtaFactory):
    """POTA concrete class

    @param dispatcher_callbacks: Callbacks in Dispatcher object
    """

    def __init__(self, repo_type: str, dispatcher_callbacks: DispatcherCallbacks) -> None:

        super().__init__(repo_type, dispatcher_callbacks)

    def create_parser(self) -> OtaParser:
        logger.debug(" ")
        return PotaParser(self._repo_type, self._dispatcher_callbacks)

    def create_thread(self, parsed_manifest: Mapping[str, Optional[Any]]):
        logger.debug(" ")
        pass
