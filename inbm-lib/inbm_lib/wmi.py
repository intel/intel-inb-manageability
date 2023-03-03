"""
    Functions for calling and parsing wmic tool output on Windows

    @copyright: Copyright 2020-2023 Intel Corporation All Rights Reserved.
    @license: SPDX-License-Identifier: Apache-2.0
"""
import logging

from typing import Dict, Optional

from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.wmi_exception import WmiException

logger = logging.getLogger(__name__)


def parse_wmic_output(wmic_output: str) -> Dict[str, str]:
    """Parse output of wmic query

    See test cases.

    @param wmic_output: Output from wmic tool
    @return Dictionary with key/value from wmic"""
    try:
        non_blank_lines = [s for s in wmic_output.splitlines() if s]
        parsed = {non_blank_lines[0].rstrip(' '): non_blank_lines[1].rstrip(' ')}
        logger.debug("Parsed wmic output: {}".format(str(parsed)))
    except IndexError as error:
        logger.error(f"Failed to parse {wmic_output}")
        return {"": ""}
    return parsed


def wmic_query(system: str, attribute: str) -> Dict[str, str]:
    """Run wmic query

    Run: "wmic <system> get <attribute>" and return output in parsed dictionary form.

    E.g., wmic could return
    Foo
    bar

    And this function would return: {'Foo': 'bar'}

    Raises WmiException on error.
    """
    logger.debug("")
    cmd = f"wmic {system} get {attribute}"
    try:
        (output, err, code) = PseudoShellRunner.run(cmd)
    except BaseException as exception:
        logger.error(f"wmic could not be run: {exception}")
        raise WmiException from exception
    if code == 0:
        return parse_wmic_output(output)
    else:
        error = "wmic failed--exit code {}".format(str(code))
        logger.error(error)
        raise WmiException(error)
