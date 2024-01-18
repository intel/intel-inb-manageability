"""
    Creates concrete classes based on OS Type and type of source file being manipulated.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging

from dispatcher.source.constants import OsType
from dispatcher.source.source_manager import ApplicationSourceManager, OsSourceManager
from typing import Optional, Any
from dispatcher.source.ubuntu_source_manager import (
    UbuntuApplicationSourceManager,
    UbuntuOsSourceManager,
)

logger = logging.getLogger(__name__)


def create_os_source_manager(os_type: OsType) -> OsSourceManager:
    """Return correct OS source manager based on OS type"""
    if os_type is OsType.Ubuntu:
        return UbuntuOsSourceManager()
    raise ValueError(f"Unsupported OS type: {os_type}.")


def create_application_source_manager(os_type: OsType, dispatcher_broker: Optional[Any] = None) -> ApplicationSourceManager:
    """Return correct OS application manager based on OS type"""
    if os_type is OsType.Ubuntu:
        return UbuntuApplicationSourceManager(dispatcher_broker)
    raise ValueError(f"Unsupported OS type: {os_type}.")
