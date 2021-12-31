"""
    Validator methods for manifests

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import os
import logging

from .constant import XLINK_SCHEMA_LOCATION, VisionException
from .configuration_constant import KEY_MANIFEST
from inbm_vision_lib.constants import CACHE_MANAGEABILITY
from inbm_vision_lib.xml_handler import XmlException, XmlHandler

logger = logging.getLogger(__name__)


def validate_key(manifest_key: str) -> None:
    """validate if the key is valid before passing the request

    @param manifest_key: key to validate
    """
    logger.debug('Checking manifest key = {}'.format(manifest_key))
    key_value = manifest_key.split(":", 1)
    check_key = key_value[0]
    if CACHE_MANAGEABILITY == (os.path.dirname(check_key)):
        pass
    elif any(x in check_key for x in KEY_MANIFEST):
        pass
    else:
        raise VisionException(
            "Invalid Key Manifest : {0}".format(check_key))


def validate_xlink_message(xlink_message: str) -> None:
    """Check the validity of xlink message.

    @param xlink_message: xlink manifest to be validated
    """
    try:
        XmlHandler(xml=xlink_message, schema_location=XLINK_SCHEMA_LOCATION)
    except XmlException as error:
        raise VisionException(
            "Xlink message validation fail. Error: {0}".format(error))
