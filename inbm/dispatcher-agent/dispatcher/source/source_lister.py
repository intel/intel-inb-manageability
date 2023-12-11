"""
    Creates and returns an OS and command specific lister for listing source commands in the source file or source
    file list

    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class SourceLister(ABC):
    """Base class for listing sources."""

    def __init__(self) -> None:
        pass

    @abstractmethod
    def list(self) -> None:
        """Lists sources in a source file or source file list."""
        pass


class UbuntuOsSourceLister(SourceLister):
    """Derived class. Lists sources from the Ubuntu OS source file /etc/apt/sources.list"""

    def __init__(self) -> None:
        super().__init__()

    def list(self) -> None:
        """Lists sources from the Ubuntu OS source file /etc/apt/sources.list"""
        # TODO: Add functionality to lists sources from the Ubuntu OS source file /etc/apt/sources.list
        pass


class UbuntuApplicationSourceLister(SourceLister):
    """Derived class. Lists sources for Ubuntu under /etc/apt/sources.list.d"""

    def __init__(self) -> None:
        super().__init__()

    def list(self) -> None:
        """Lists Ubuntu sources under /etc/apt/sources.list.d"""
        # TODO: Add functionality to lists all sources stored under /etc/apt/sources.list.d
        pass
