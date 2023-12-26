"""
    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from enum import Enum, unique
from dataclasses import dataclass, field

UBUNTU_APT_SOURCES_LIST = "/etc/apt/sources.list"
UBUNTU_APT_SOURCES_LIST_D = "/etc/apt/sources.list.d"


@dataclass(kw_only=True, frozen=True)
class ApplicationSourceList:
    name: str
    sources: list[str]


@dataclass(kw_only=True)
class SourceParameters:
    sources: list[str] = field(default_factory=lambda: [])


@dataclass(kw_only=True)
class ApplicationAddSourceParameters:
    gpg_key_path: str
    gpg_key_name: str
    file_name: str
    sources: list[str] = field(default_factory=lambda: [])


@dataclass(kw_only=True)
class ApplicationRemoveSourceParameters:
    gpg_key_id: str
    file_name: str


@dataclass()
class ApplicationUpdateSourceParameters:
    file_name: str
    sources: list[str] = field(default_factory=lambda: [])


@unique
class OsType(Enum):
    """Supported Operating Systems."""
    Ubuntu = 0
    # Windows = 1 # Not currently supported
