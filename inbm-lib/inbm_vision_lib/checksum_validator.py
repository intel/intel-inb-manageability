"""
    Checksum related validation.

    Copyright (C) 2019-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
import hashlib
from .constants import SecurityException

logger = logging.getLogger(__name__)


def hash_message(message):
    return hashlib.sha384(message.encode()).hexdigest()


def validate_message(message, original_message):
    logger.debug("Validating checksum...")
    if message != hash_message(original_message):
        logger.error("Invalid Checksum")
        raise SecurityException(
            "Checksum validation failed on the received message on Xlink")
    else:
        logger.debug("Checksum Validated...")
