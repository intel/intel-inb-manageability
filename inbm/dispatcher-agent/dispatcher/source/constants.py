"""
    Copyright (C) 2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from enum import Enum, unique
from dataclasses import dataclass, field
from typing import List


@dataclass(kw_only=True)
class SourceParameters:
    sources: List[str] = field(default_factory=lambda: [])


@dataclass(kw_only=True)
class ApplicationAddSourceParameters(SourceParameters):
    gpg_key_path: str
    gpg_key_name: str
    file_name: str


@dataclass(kw_only=True)
class ApplicationRemoveSourceParameters(SourceParameters):
    gpg_key_id: str
    file_name: str


@dataclass(kw_only=True)
class ApplicationUpdateSourceParameters(SourceParameters):
    file_name: str


@unique
class SourceCmdType(Enum):
    """Source Type to manipulate
    OS - Source files related to the operating system
    Application - Source files related to installed applications
    """

    OS = ["os"]
    Application = ["application"]


@unique
class OsType(Enum):
    """Supported Operating Systems."""
    Ubuntu = 0
    # Windows = 1 # Not currently supported
