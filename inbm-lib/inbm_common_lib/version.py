""" Parse inbm/inbm-vision version file information

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import re
from typing import Optional


def read_version(version_data: str) -> Optional[str]:
    """Parse version string from version data
    @param version_data: Contents of version file
    @return: version, or None if not found
    """
    p = re.compile('.*Version: ([^\n\r]*)', re.DOTALL)
    match = p.match(version_data)
    if match is None:
        return None
    version = match.group(1)

    return version


def read_commit(version_data: str) -> Optional[str]:
    """Parse commit string from version data
    @param version_data: Contents of version file
    @return: commit, or None if not found
    """
    p = re.compile('.*Commit: ([^\n\r]*)', re.DOTALL)
    match = p.match(version_data)
    if match is None:
        return None
    commit = match.group(1)

    return commit

