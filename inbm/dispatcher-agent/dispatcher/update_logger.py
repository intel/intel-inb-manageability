"""
    Class for creating UpdateLogger objects to record OTA update status

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import os
import json
import re
import datetime
import logging
from typing import Optional
from dataclasses import dataclass
from inbm_common_lib.shell_runner import PseudoShellRunner

from inbm_lib.constants import LOG_FILE, GRANULAR_LOG_FILE, SYSTEM_HISTORY_LOG_FILE, OTA_PENDING, FORMAT_VERSION, \
    SOTA

logger = logging.getLogger(__name__)


class UpdateLogger:
    """UpdateLogger class stores the OTA update information and generates
       log file.
    @param ota_type: Type of OTA
    @param data: meta-data of the OTA
    """

    def __init__(self, ota_type: str, data: str, package_list: str = "") -> None:
        self.status = ""
        self.ota_type = ota_type
        self.package_list: str = package_list
        self._time = datetime.datetime.now()
        self.metadata = data
        self.error = ""

    def set_time(self) -> None:
        """Set the OTA starting time."""
        self._time = datetime.datetime.now()

    def save_log(self) -> None:
        """Save the log to a log file."""
        log = {'Status': self.status,
               'Type': self.ota_type,
               'Time': self._time.strftime("%Y-%m-%d %H:%M:%S"),
               'Metadata': self.metadata,
               'Error': self.error,
               'Version': FORMAT_VERSION}

        self.write_log_file(json.dumps(log))

    def write_log_file(self, log: str) -> None:
        try:
            with open(LOG_FILE, 'w') as log_file:
                log_file.write(log)
        except OSError as e:
            logger.error(f'Error {e} on writing the file {LOG_FILE}')

    def update_log(self, status: str) -> None:
        """Update the log file after OTA reboot.
        If dispatcher state file check is passing, the status changes to SUCCESS.
        If dispatcher state file check is failing, the status changes to FAIL.

        @param status: status to be set
        """
        log = self.read_log_file()

        if log:
            log = log.replace(OTA_PENDING, status)
            self.write_log_file(log)

    def read_log_file(self) -> Optional[str]:
        try:
            with open(LOG_FILE, 'r') as log_file:
                return log_file.read()
        except OSError as e:
            logger.error(f'Error {e} on opening the file {LOG_FILE}')
            return None

    def save_granular_log_file(self) -> None:
        """Add package level granular update status data to the granular log file"""
        logger.debug(f"ota_type={self.ota_type}")
        # If the granular log file doesn't exist, create it. The file will be deleted by PUA when update done/failed.
        if not os.path.exists(GRANULAR_LOG_FILE):
            logger.debug(f"File not exist. Creating the {GRANULAR_LOG_FILE}...")
            with open(GRANULAR_LOG_FILE, "w") as file:
                pass  # Creates an empty file
        if self.ota_type == SOTA:
            logger.debug(f"ota_type={self.ota_type}")
            if self.package_list != "":
                # SOTA package installation with package list
                self.update_granular_with_sota_package_list_install()
            else:
                # Treat it as regular sota package upgrade
                self.update_granular_with_sota_package_upgrade()
        else:
            logger.debug(f"Unsupported ota_type:{self.ota_type} to record granular data.")

    def update_granular_with_sota_package_upgrade(self) -> None:
        """This function checks the latest upgrade in history log file and extract the package information.
           The package information such as package name and version will be stored in granular log file.
        """
        log_data = self.read_history_log_file()
        if log_data:
            # Get the latest upgrade history
            # Split the log into parts
            parts = log_data.split('\n\n')
            # Filter parts that contain 'upgrade'
            upgrade_parts = [part for part in parts if 'upgrade' in part.lower()]
            latest_upgrade = upgrade_parts[-1]
            update_time = ""
            match = re.search(r'Start-Date: (\d{4}-\d{2}-\d{2}  \d{2}:\d{2}:\d{2})', latest_upgrade)
            if match:
                date_str = match.group(1)
                # Parse the date string and convert to ISO 8601 format
                update_time = datetime.strptime(date_str, '%Y-%m-%d  %H:%M:%S').isoformat()
                logger.debug(f"Update time in ISO 8601 format: {update_time}")
            else:
                logger.debug("Start-Date not found.")

            # Extract the upgrade line
            upgrade_line = [line for line in latest_upgrade.split('\n') if 'Upgrade:' in line][0]
            # Use regex to split on commas not inside parentheses
            packages = re.split(r',\s*(?![^()]*\))', upgrade_line.replace('Upgrade: ', ''))
            # Create a dictionary to store package names and their versions
            package_dict = {}
            # Loop through each package string and extract the name and version
            for package in packages:
                name_version = re.match(r"(.+?)\s+\((.+)\)", package)
                if name_version:
                    name = name_version.group(1).strip()
                    version = name_version.group(2).strip()
                    package_dict[name] = version

            # Load current data in granular log file.
            with open(GRANULAR_LOG_FILE, 'r') as f:
                data = json.load(f)

            # Create the package information and store it
            for package_name, version in package_dict.items():
                logger.debug(f"Package: {package_name}, Version: {version}")
                shell = PseudoShellRunner()
                status, err, code = shell.run(
                    "dpkg-query -W -f='${Status}\n' " + package_name)
                if err:
                    logger.error(f"Error in getting the package: {package_name} Error: {err}")
                    status = "unknown"

                package_info = {
                    "update_type": "os",
                    "package_name": package_name,
                    "update_time": update_time,
                    "action": "upgrade",
                    "status": status,
                    "version": version
                }
                # Append the new package information to the UpdateLog list
                data['UpdateLog'].append(package_info)

            # Open the file in write mode to save the updated data
            with open(GRANULAR_LOG_FILE, 'w') as f:
                json.dump(data, f, indent=4)

    def update_granular_with_sota_package_list_install(self) -> None:
        """This function checks the latest package installation information in history log file.
           It extracts the package information such as package name and version.
           These information will be stored in granular log file.
        """
        # Load current data in granular log file.
        with open(GRANULAR_LOG_FILE, 'r') as f:
            data = json.load(f)

        for package_name in self.package_list:
            #  Get status
            shell = PseudoShellRunner()
            status, err, code = shell.run(
                "dpkg-query -W -f='${Status}\n' " + package_name)
            if err:
                logger.error(f"Error in getting the package's status: {package_name} Error: {err}")
                status = "unknown"

            # Get Version
            version, err, code = shell.run(
                "dpkg-query -W -f='${Version}\n' " + package_name)
            if err:
                logger.error(f"Error in getting the package's version: {package_name} Error: {err}")
                status = "unknown"
            package_info = {
                "update_type": "os",
                "package_name": package_name,
                "update_time": self._time.isoformat(),
                "action": "install",
                "status": status,
                "version": version
            }

            # Append the new package information to the UpdateLog list
            data['UpdateLog'].append(package_info)

            # Open the file in write mode to save the updated data
            with open(GRANULAR_LOG_FILE, 'w') as f:
                json.dump(data, f, indent=4)

    def read_history_log_file(self) -> Optional[str]:
        """Read the apt history log file.

        @return: content of the history log file
        """
        try:
            with open(SYSTEM_HISTORY_LOG_FILE, 'r') as log_file:
                return log_file.read()
        except OSError as e:
            logger.error(f'Error {e} on opening the file {SYSTEM_HISTORY_LOG_FILE}')
            return None
