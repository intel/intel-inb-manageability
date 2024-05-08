"""
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import json
import logging
import os
import jsonschema
from typing import Optional, Tuple

from inbm_lib.xmlhandler import XmlHandler
from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_lib.security_masker import mask_security_info

from .constants import *

logger = logging.getLogger(__name__)


def get_schema_location(schema_type: str, schema_location: Optional[str] = None) -> str:
    if not schema_location:
        schema_location = JSON_SCHEMA_LOCATION
    return schema_location

def validate_xml_manifest(xml: str,
                          schema_location: Optional[str] = None) -> Tuple[str, XmlHandler]:
    """Parse manifest

    @param xml: manifest in XML format
    @param schema_location: optional location of schema
    @return: Tuple of (ota-type, resource-name, URL of resource, resource-type)
    """
    # Added schema_location variable for unit tests
    schema_location = get_canonical_representation_of_path(
        schema_location) if schema_location is not None else get_canonical_representation_of_path(SCHEMA_LOCATION)
    parsed = XmlHandler(xml=xml,
                        is_file=False,
                        schema_location=schema_location)
    type_of_manifest = parsed.get_element('type')
    logger.debug(
        f"type_of_manifest: {type_of_manifest!r}. parsed: {mask_security_info(str(parsed))!r}.")
    return type_of_manifest, parsed

def _validate_json_schema(schema_type: str, params: str, schema_location: Optional[str] = None) -> str:
    schema_location = get_schema_location(schema_type, schema_location)

    if not os.path.exists(schema_location):
        logger.error("JSON Schema file not found")
        raise ValueError("JSON Schema file not found")

    try:
        with open(get_canonical_representation_of_path(schema_location)) as schema_file:
            schema = json.loads(schema_file.read())

        parsed = json.loads(str(params))
        jsonschema.validate(parsed, schema)
    except (ValueError, OSError, jsonschema.exceptions.ValidationError):
        raise ValueError("Schema validation failed!")
    return parsed


def is_valid_config_params(config_params: str, schema_location: Optional[str] = None) -> bool:
    """Schema validate the configuration parameters

    @param config_params: params to be validated
    @param schema_location: location of schema file; default=None
    @return (bool): True if schema validated or False on failure or exception
    """
    try:
        _validate_json_schema('single', config_params, schema_location)
    except (ValueError, KeyError, jsonschema.exceptions.ValidationError) as e:
        logger.info("Error received: %s", str(e))
        return False
    return True
