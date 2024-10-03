"""
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import json
import logging
import os
import jsonschema
from typing import Optional, Any

from inbm_common_lib.utility import get_canonical_representation_of_path

from .constants import CONFIG_JSON_SCHEMA_LOCATION

logger = logging.getLogger(__name__)


def _get_schema_location(schema_location: Optional[str] = None) -> str:
    if not schema_location:
        schema_location = CONFIG_JSON_SCHEMA_LOCATION
    return schema_location

"""Validates JSON against a JSON schema

@param params: JSON Parameters
@param schema_location: JSON schema location.  Default=NONE
@return: Deserialized JSON
"""
def _validate_schema(params: str, schema_location: Optional[str] = None) -> Any:
    schema_location = _get_schema_location(schema_location)

    if not os.path.exists(schema_location):
        logger.error("JSON Schema file not found")
        raise ValueError("JSON Schema file not found")

    try:
        with open(get_canonical_representation_of_path(schema_location)) as schema_file:
            schema = json.loads(schema_file.read())

        parsed = json.loads(str(params))
        jsonschema.validate(parsed, schema)
    except (ValueError, OSError, jsonschema.exceptions.ValidationError) as e:
        raise ValueError(f"Schema validation failed! Error: {e}")
    return parsed             


def is_valid_json_structure(json_params: str, schema_location: Optional[str] = None) -> bool:
    """Validate the JSON structure against the schema

    @param json_params: JSON params to be validated
    @param schema_location: location of schema file; default=None
    @return (bool): True if valid schema; otherwise, False
    """
    try:
        _validate_schema(json_params, schema_location)
    except (ValueError, KeyError, jsonschema.exceptions.ValidationError) as e:
        logger.info("Error validating JSON structure against schema: %s", str(e))
        return False
    return True
