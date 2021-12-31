# -*- coding: utf-8 -*-
"""
    Mender utility functions

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from .constant import MENDER_ARTIFACT_PATH


def read_current_mender_version() -> str:
    """Reads current booted Mender version from root filesystem.

    @return (bytes) version
    """

    with open(MENDER_ARTIFACT_PATH, 'rb') as content_file:
        content = content_file.read()

    return content.decode('utf-8', errors='strict').strip('artifact_name=')
