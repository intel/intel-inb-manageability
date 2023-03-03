"""
    SOTA upgrade abstract and concrete classes.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from typing import List

from .command_list import CommandList

logger = logging.getLogger(__name__)


class OsUpgrader:
    """Base class for handling os upgrade related task for the system."""

    def __init__(self) -> None:
        self.cmd_list: List = []

    def upgrade(self):
        """Upgrade command overridden from factory. It builds the commands for Ubuntu upgrade in
        Internal command store

        @return: command list
        """
        pass

    def build_command_checklist(self, cmds: List):
        """ Populate the command list and command's internal data store

        @param cmds:  the dictionary of commands from parsed manifest
        """
        logger.debug("")
        self.cmd_list = CommandList(cmds).cmd_list


class UbuntuUpgrader(OsUpgrader):
    """UbuntuUpgrader class, child of OsUpgrader"""

    def __init__(self) -> None:
        super().__init__()

    def upgrade(self) -> List:
        """Upgrade command overridden from factory. It builds the commands for Ubuntu upgrade
        in Internal command store

        @return: returns file to log the upgrade to
        """
        logger.debug("")
        full_command = ['do-release-upgrade -f DistUpgradeViewNonInteractive']
        self.build_command_checklist(full_command)
        return self.cmd_list


class WindowsUpgrader(OsUpgrader):
    """WindowsUpgrader class, child of OsUpgrader"""

    def __init__(self) -> None:
        super().__init__()

    def upgrade(self):
        """Upgrade command overridden from factory. It builds the commands for Windows upgrade
        in Internal command store

        @return: returns file to log the upgrade to
        """
        logger.debug("")
        pass


class YoctoUpgrader(OsUpgrader):
    """YoctoUpgrader class, child of OsUpgrader"""

    def __init__(self) -> None:
        super().__init__()

    def upgrade(self) -> List:
        """Upgrade command overridden from factory. It builds the commands for Yocto upgrade in
        Internal command store

        @return: command list
        """
        logger.debug("")
        logger.debug("Yocto upgrade is currently not supported")
        cmds = ['uname']
        self.build_command_checklist(cmds)
        return self.cmd_list
