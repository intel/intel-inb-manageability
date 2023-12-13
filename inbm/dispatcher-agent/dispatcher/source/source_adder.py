"""
    Creates and returns an OS and command specific adder for adding source commands to a source file or source file list

    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from abc import ABC, abstractmethod
from .constants import SourceParameters, ApplicationAddSourceParameters

logger = logging.getLogger(__name__)


class SourceAdder(ABC):
    """Base class for adding commands to a source file or source file list for future updates."""

    def __init__(self) -> None:
        pass

    @abstractmethod
    def add(self, parameters: SourceParameters) -> None:
        """Adds a source file to a source file or source file list for future updates."""
        pass


class UbuntuOsSourceAdder(SourceAdder):
    """Derived class. Adds a source file to the Ubuntu OS source file /etc/apt/sources.list"""

    def __init__(self) -> None:
        super().__init__()

    def add(self, parameters: SourceParameters) -> None:
        """Adds a source in the Ubuntu OS source file /etc/apt/sources.list"""
        # TODO: Add functionality to add a source file in Ubuntu to /etc/apt/sources.list file
        logger.debug(f"sources: {parameters.source}")


class UbuntuApplicationSourceAdder(SourceAdder):
    """Derived class. Adds a new source file to the Ubuntu OS source file list under /etc/apt/sources.list.d"""

    def __init__(self) -> None:
        super().__init__()

    def add(self, parameters: ApplicationAddSourceParameters) -> None:
        """Adds a new source file to the Ubuntu OS source file list under /etc/apt/sources.list.d"""
        # TODO: Add functionality to add a new source file to the Ubuntu OS source file list
        #  under /etc/apt/sources.list.d
        logger.debug(f"gpg_key_path: {parameters.gpg_key_path}, gpg_key_name: {parameters.gpg_key_name},"
                     f"sources: {parameters.source[0]}, file_name: {parameters.file_name}")
