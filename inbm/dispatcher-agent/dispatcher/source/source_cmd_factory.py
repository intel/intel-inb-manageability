"""
    Creates concrete classes based on OS Type and type of source file being manipulated.

    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
from abc import ABC, abstractmethod
from typing import Type

from .source_adder import SourceAdder, UbuntuOsSourceAdder, UbuntuApplicationSourceAdder
from .source_remover import SourceRemover, UbuntuOsSourceRemover, UbuntuApplicationSourceRemover
from .source_updater import SourceUpdater, UbuntuOsSourceUpdater, UbuntuApplicationSourceUpdater
from .source_lister import SourceLister, UbuntuApplicationSourceLister, UbuntuOsSourceLister
from .constants import OsType, SourceCmdType

logger = logging.getLogger(__name__)


class SourceCommandFactory(ABC):
    """Abstract Factory for creating the concrete classes based on the OS Type and Source
        command type (OS and Application).
    """

    def __init__(self) -> None:
        pass

    @abstractmethod
    def create_adder(self) -> SourceAdder:
        """Creates and returns an OS and command specific adder for adding source commands to a source file

        @return OS and command specific SourceAdder
        """
        pass

    @abstractmethod
    def create_remover(self) -> SourceRemover:
        """Creates and returns an OS and command specific remover for removing source commands from a file

        @return OS and command specific SourceRemover
        """
        pass

    @abstractmethod
    def create_updater(self) -> SourceUpdater:
        """Creates and returns an OS and command specific updater for updating source commands
        in a source related file

        @return OS and command specific SourceRemover
        """
        pass

    @abstractmethod
    def create_lister(self) -> SourceLister:
        """Creates and returns an OS and command specific lister for listing the existing source commands
        in a source related file

        @return OS and command specific SourceLister
        """
        pass


class UbuntuOsCommandFactory(SourceCommandFactory):
    """Abstract Factory for creating the OS command type concrete classes.  This instance is for Ubuntu.
    """

    def __init__(self) -> None:
        super().__init__()

    def create_adder(self) -> SourceAdder:
        """Creates and returns Ubuntu based source adder to add source commands to the Ubuntu source file
         (/etc/apt/sources.list').  This file is used to determine what is updated when performing the
         'apt update' command.

        @return Ubuntu specific SourceAdder of OS style source files
        """
        return UbuntuOsSourceAdder()

    def create_remover(self) -> SourceRemover:
        """Creates and returns Ubuntu based source remover to remove source commands in the Ubuntu source file
         (/etc/apt/sources.list').  This file is used to determine what is updated when performing the
         'apt update' command.

        @return Ubuntu specific SourceRemover of OS style source files
        """
        return UbuntuOsSourceRemover()

    def create_updater(self) -> SourceUpdater:
        """Creates and returns Ubuntu based source updater to update source commands in the Ubuntu source file
         (/etc/apt/sources.list').  This file is used to determine what is updated when performing the
         'apt update' command.

        @return Ubuntu specific SourceUpdater of OS style source files
        """
        return UbuntuOsSourceUpdater()

    def create_lister(self) -> SourceLister:
        """Creates and returns Ubuntu based source lister to list source commands in the Ubuntu source file
         (/etc/apt/sources.list').  This file is used to determine what is updated when performing the
         'apt update' command.

        @return Ubuntu specific SourceLister of OS style source files
        """
        return UbuntuOsSourceLister()


class UbuntuApplicationCommandFactory(SourceCommandFactory):
    """Abstract Factory for creating the Application command type concrete classes.  This instance is for Ubuntu.
    """

    def __init__(self) -> None:
        super().__init__()

    def create_adder(self) -> SourceAdder:
        """Creates and returns Ubuntu based source adder to add source commands to the Ubuntu source file list
         under (/etc/apt/sources.list.d').  This list is used to determine what is updated when performing the
         'apt update' command.

        @return Ubuntu specific SourceAdder of Application style source files
        """
        return UbuntuApplicationSourceAdder()

    def create_remover(self) -> SourceRemover:
        """Creates and returns Ubuntu based source remover to remove source commands in the Ubuntu source file list
         under (/etc/apt/sources.list.d').  This file is used to determine what is updated when performing the
         'apt update' command.

        @return Ubuntu specific SourceRemover of Application style source files
        """
        return UbuntuApplicationSourceRemover()

    def create_updater(self) -> SourceUpdater:
        """Creates and returns Ubuntu based source updater to update source commands in the Ubuntu source file list
         under (/etc/apt/sources.list').  This file is used to determine what is updated when performing the
         'apt update' command.

        @return Ubuntu specific SourceUpdater of Application style source files
        """
        return UbuntuApplicationSourceUpdater()

    def create_lister(self) -> SourceLister:
        """Creates and returns Ubuntu based source lister to list source commands in the Ubuntu source file list
         under (/etc/apt/sources.list').  This file is used to determine what is updated when performing the
         'apt update' command.

        @return Ubuntu specific SourceLister of Application style source files
        """
        return UbuntuApplicationSourceLister()


def get_factory(os_type: OsType, source_type: SourceCmdType) -> SourceCommandFactory:
    """Gets the correct abstract factory based on the OS detected and the source command type

    @param os_type: OS type detected
    @param source_type: Type of Source to add for updates
    @return: Abstract Factory of detected OS and source command type
    """

    if os_type is OsType.Ubuntu:
        return UbuntuOsCommandFactory() if source_type is SourceCmdType.OS else UbuntuApplicationCommandFactory()
    raise ValueError(f'Unsupported OS type: {os_type}.')
