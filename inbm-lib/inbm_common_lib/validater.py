""" User import validation

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import datetime
import argparse
from dataclasses import dataclass
import re
logger = logging.getLogger(__name__)


def validate_string_less_than_n_characters(value: str, param_type: str, max_size: int) -> str:
    """Validates that the user inputted string does not exceed the maximum allowed
        @param value: string entered by user
        @param param_type: parameter type
        @param max_size: maximum size allowed for the string
        @return: entered string if it passes the length check
        @raise argparse.ArgumentTypeError: Invalid date format
        """
    if len(value) > max_size:
        raise argparse.ArgumentTypeError(
            "{} is greater than allowed string size: {}".format(param_type, str(value)))
    return value


def validate_date(date: str) -> str:
    """Validates that the date is in the correct format
    @param date: date provided by the user
    @return: valid date
    @raise argparse.ArgumentTypeError: Invalid date format
    """
    try:
        return str(datetime.datetime.strptime(date, "%Y-%m-%d").date())
    except ValueError:
        raise argparse.ArgumentTypeError(f"Not a valid date - format YYYY-MM-DD: '{date}")

def validate_guid(value: str) -> str:
    """Validates that the user inputted string does not exceed the maximum allowed
        @param value: string entered by user
        @raise argparse.ArgumentTypeError: Invalid guid format
        """
    if not bool(re.match("^[{]?[0-9a-fA-F]{8}" + "-([0-9a-fA-F]{4}-)" + "{3}[0-9a-fA-F]{12}[}]?$", str(value))):
        raise argparse.ArgumentTypeError(f"GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed")
    return value

@dataclass
class ConfigurationItem:
    """Class for keeping track of an item in inventory."""
    key: str
    lower_limit: int
    upper_limit: int
    default_value: int


def configuration_bounds_check(item: ConfigurationItem, value: int) -> int:
    if item.lower_limit <= int(value) <= item.upper_limit:
        return value
    else:
        logger.error(f'{item.key} is outside of the allowed limits: '
                     f'{item.lower_limit}-{item.upper_limit}.  '
                     f'Using the default value: {item.default_value}.')
        return item.default_value
