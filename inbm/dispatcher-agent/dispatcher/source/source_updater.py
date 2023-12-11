"""
    Creates and returns an OS and command specific remover for removing source commands from a source file or source
    file list

    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class SourceUpdater(ABC):
    """Base class for updating commands in the source file or source file list for future updates."""

    def __init__(self) -> None:
        pass

    @abstractmethod
    def update(self) -> None:
        """Updates a source file from a source file or source file list for future updates."""
        pass


class UbuntuOsSourceUpdater(SourceUpdater):
    """Derived class. Updates a source in the Ubuntu OS source file /etc/apt/sources.list"""

    def __init__(self) -> None:
        super().__init__()

    def update(self) -> None:
        """Updates a source in the Ubuntu OS source file /etc/apt/sources.list"""
        # TODO: Add functionality to update a source in Ubuntu file under /etc/apt/sources.list file
        pass


class UbuntuApplicationSourceUpdater(SourceUpdater):
    """Derived class. Updates a source file in Ubuntu OS source file list under /etc/apt/sources.list.d"""

    def __init__(self) -> None:
        super().__init__()

    def update(self) -> None:
        """Updates a source file in Ubuntu OS source file list under /etc/apt/sources.list.d"""
        # TODO: Add functionality to update a Ubuntu source file under /etc/apt/sources.list.d
        pass
