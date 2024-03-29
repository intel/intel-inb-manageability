"""
    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from enum import Enum, unique
from dataclasses import dataclass, field
from typing import Optional, List

UBUNTU_APT_SOURCES_LIST = "/etc/apt/sources.list"
UBUNTU_APT_SOURCES_LIST_D = "/etc/apt/sources.list.d"
LINUX_GPG_KEY_PATH = "/usr/share/keyrings"


@dataclass(kw_only=True, frozen=True)
class ApplicationSourceList:
    name: str
    sources: list[str]


@dataclass(kw_only=True, frozen=True)
class SourceParameters:
    sources: List[str] = field(default_factory=list)


@dataclass(kw_only=True, frozen=True)
class ApplicationAddSourceParameters:
    source_list_file_name: str
    sources: List[str] = field(default_factory=list)
    gpg_key_uri: Optional[str] = field(default=None)
    gpg_key_name: Optional[str] = field(default=None)


@dataclass(kw_only=True, frozen=True)
class ApplicationRemoveSourceParameters:
    source_list_file_name: str
    gpg_key_name: Optional[str] = field(default=None)


@dataclass(kw_only=True, frozen=True)
class ApplicationUpdateSourceParameters:
    source_list_file_name: str
    sources: List[str] = field(default_factory=list)


@unique
class OsType(Enum):
    """Supported Operating Systems."""

    Ubuntu = 0
    # Windows = 1 # Not currently supported
