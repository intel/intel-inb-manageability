"""
    Util to get the package information.

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import re
import datetime
import logging
from typing import Dict
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_lib.constants import PACKAGE_SUCCESS, PACKAGE_PENDING, PACKAGE_FAIL, PACKAGE_UNKNOWN

logger = logging.getLogger(__name__)


def get_package_start_date(text: str) -> str:
    """Extract the package start date a given text.

    @return: string representing the start date in isoformat.
    """
    match = re.search(r'Start-Date: (\d{4}-\d{2}-\d{2}  \d{2}:\d{2}:\d{2})', text)
    if match:
        # Parse the date string and convert to ISO 8601 format
        return datetime.datetime.strptime(match.group(1), '%Y-%m-%d  %H:%M:%S').isoformat()
    else:
        return ""


def extract_package_names_and_versions(text: str) -> Dict[str, str]:
    """Extract the package name and version from a given text.
    The text will be the content of the Upgrade part in /var/log/apt/history.log.

    @return: a dict that contains package's name and its version
    """
    # Create a dictionary to store package names and their versions
    package_dict = {}
    try:
        # Extract the upgrade line
        upgrade_lines = [line for line in text.split('\n') if 'Upgrade:' in line]
        if upgrade_lines:
            upgrade_line = upgrade_lines[0]
        else:
            raise KeyError
        # Use regex to split on commas not inside parentheses
        packages = re.split(r',\s*(?![^()]*\))', upgrade_line.replace('Upgrade: ', ''))

        # Loop through each package string and extract the name and version
        for package in packages:
            name_version = re.match(r"(.+?)\s+\((.+)\)", package)
            if name_version:
                name = name_version.group(1).strip()
                version = name_version.group(2).strip()
                package_dict[name] = version
    except (IndexError, KeyError):
        logger.debug(f"No Upgrade Packages found in text:{text}")
        return package_dict
    return package_dict


def check_package_status(package_name: str) -> str:
    """Check the package installation status using dpkg-query command.

    @return: status of the package
    """
    shell = PseudoShellRunner()
    out, err, code = shell.run(
        "dpkg-query -W -f='${Status}\n' " + package_name)
    if err:
        logger.error(f"Error in getting the package's status: {package_name} Error: {err}")
        return PACKAGE_FAIL

    if "unknown ok not-installed" in out or "deinstall ok config-files" in out:
        return PACKAGE_PENDING

    if "install ok installed" in out:
        return PACKAGE_SUCCESS

    return PACKAGE_UNKNOWN


def check_package_version(package_name: str) -> str:
    """Check the package version using dpkg-query command.

    @return: version of the package
    """
    shell = PseudoShellRunner()
    version, err, code = shell.run(
        "dpkg-query -W -f='${Version}\n' " + package_name)
    if err:
        logger.error(f"Error in getting the package's version: {package_name} Error: {err}")
        return PACKAGE_UNKNOWN
    return version
