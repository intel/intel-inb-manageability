"""
    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from abc import ABCMeta, abstractmethod

from dispatcher.source.constants import (
    ApplicationAddSourceParameters,
    ApplicationRemoveSourceParameters,
    ApplicationSourceList,
    ApplicationUpdateSourceParameters,
    SourceParameters,
)


class OsSourceManager(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self) -> None:
        pass

    @abstractmethod
    def add(self, parameters: SourceParameters) -> None:
        """Adds sources to the OS source list"""
        pass

    @abstractmethod
    def list(self) -> list[str]:
        """Lists sources from OS source list"""
        pass

    @abstractmethod
    def remove(self, parameters: SourceParameters) -> None:
        """Removes sources from OS source list"""
        pass

    @abstractmethod
    def update(self, parameters: SourceParameters) -> None:
        """Updates sources in OS source list"""
        pass


class ApplicationSourceManager(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self) -> None:
        pass

    @abstractmethod
    def add(self, parameters: ApplicationAddSourceParameters) -> None:
        """Adds a new application source along with key"""
        pass

    @abstractmethod
    def list(self) -> list[ApplicationSourceList]:
        """Lists application sources"""
        pass

    @abstractmethod
    def remove(self, parameters: ApplicationRemoveSourceParameters) -> None:
        """Removes an application source"""
        pass

    @abstractmethod
    def update(self, parameters: ApplicationUpdateSourceParameters) -> None:
        """Updates (replaces) an application source"""
        pass
