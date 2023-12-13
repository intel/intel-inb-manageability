"""
    Creates and returns an OS and command specific remover for removing source commands from a source file or source
    file list

    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from abc import ABC, abstractmethod
from .constants import SourceParameters, ApplicationRemoveSourceParameters

logger = logging.getLogger(__name__)


class SourceRemover(ABC):
    """Base class for removing commands from a source file or source file list for future updates."""

    def __init__(self) -> None:
        pass

    @abstractmethod
    def remove(self, parameters: SourceParameters) -> None:
        """Removes a source file from a source file or source file list for future updates."""
        logger.debug(f"sources: {parameters.source}")


class UbuntuOsSourceRemover(SourceRemover):
    """Derived class. Removes a source file from the Ubuntu OS source file /etc/apt/sources.list"""

    def __init__(self) -> None:
        super().__init__()

    def remove(self, parameters: SourceParameters) -> None:
        """Removes a source in the Ubuntu OS source file /etc/apt/sources.list"""
        # TODO: Add functionality to remove a source file in Ubuntu to /etc/apt/sources.list file
        logger.debug(f"sources: {parameters.source}")


class UbuntuApplicationSourceRemover(SourceRemover):
    """Derived class. Removes a source file from the Ubuntu source file list under /etc/apt/sources.list.d"""

    def __init__(self) -> None:
        super().__init__()

    def remove(self, parameters: ApplicationRemoveSourceParameters) -> None:
        """Removes a source file from the Ubuntu source file list under /etc/apt/sources.list.d"""
        # TODO: Add functionality to remove a source file under the Ubuntu source file list
        #  under /etc/apt/sources.list.d
        logger.debug(f"gpg_key_path: {parameters.gpg_key_id}, file_name: {parameters.file_name}")
