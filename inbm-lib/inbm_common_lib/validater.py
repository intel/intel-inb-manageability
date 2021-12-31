""" User import validation

    Copyright (C) 2017-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import datetime
import argparse


def validate_string_less_than_n_characters(value: str, param_type: str, max_size: int) -> str:
    """Validates that the user inputted string does not exeed the maximum allowed
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
