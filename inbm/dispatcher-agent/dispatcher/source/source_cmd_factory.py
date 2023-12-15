"""
    Creates concrete classes based on OS Type and type of source file being manipulated.

    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging

from dispatcher.source.constants import OsType
from dispatcher.source.source_cmd import SourceApplicationCommand, SourceOsCommand
from dispatcher.source.ubuntu_source_cmd import (
    UbuntuSourceApplicationCommand,
    UbuntuSourceOsCommand,
)

logger = logging.getLogger(__name__)


def create_source_os_command(os_type: OsType) -> SourceOsCommand:
    """Return correct source OS command based on OS type"""
    if os_type is OsType.Ubuntu:
        return UbuntuSourceOsCommand()
    raise ValueError(f"Unsupported OS type: {os_type}.")


def create_source_application_command(os_type: OsType) -> SourceApplicationCommand:
    """Return correct source appliaction command based on OS type"""
    if os_type is OsType.Ubuntu:
        return UbuntuSourceApplicationCommand()
    raise ValueError(f"Unsupported OS type: {os_type}.")
