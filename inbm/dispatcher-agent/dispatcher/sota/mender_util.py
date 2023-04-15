"""
    Mender utility functions

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
from .constants import MENDER_ARTIFACT_PATH
from .sota_error import SotaError
logger = logging.getLogger(__name__)


def read_current_mender_version() -> str:
    """Reads current booted Mender version from root filesystem.

    @return (bytes) version
    """
    try:
        with open(MENDER_ARTIFACT_PATH, 'rb') as content_file:
            content = content_file.read()
        return content.decode('utf-8', errors='strict').strip('artifact_name=')
    except (FileNotFoundError, IOError, OSError, ValueError, UnicodeError) as e:
        logger.debug(f"Error: {str(e)}")
        raise SotaError('failed to read mender-version from state file or'
                        ' failed to read state file')
