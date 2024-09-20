"""
    Class for creating UpdateLogger objects to record OTA update status

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import os
import json
import datetime
import logging
from typing import Optional, Dict, List, Any

from inbm_lib.constants import LOG_FILE, GRANULAR_LOG_FILE, SYSTEM_HISTORY_LOG_FILE, OTA_PENDING, FORMAT_VERSION, \
    SOTA, OS, APPLICATION, PACKAGE_INSTALL, PACKAGE_UPGRADE

from inbm_lib.detect_os import detect_os, LinuxDistType

from inbm_lib.package_info import get_package_start_date, extract_package_names_and_versions, check_package_status, \
    check_package_version

logger = logging.getLogger(__name__)


class UpdateLogger:
    """UpdateLogger class stores the OTA update information and generates
       log file.
    @param ota_type: Type of OTA
    @param data: meta-data of the OTA
    @param package_list: list of packages installed by dispatcher
    """

    def __init__(self, ota_type: str, data: str) -> None:
        self.status = ""
        self.detail_status = ""
        self.ota_type = ota_type
        self.package_list: str = ""
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

    def save_granular_log_file(self, log: Optional[dict] = None, check_package: bool = True) -> None:
        """Add package level granular update status data to the granular log file
        In TiberOS, the granular log records the reason of failure.
        If the log is passed in, it will only record the log.

        @param log: granular log to be recorded (dict)
        @param check_package: Set to True to check the package's status and version and record them.
        """
        logger.debug("")
        # If the granular log file doesn't exist, create it. The file will be deleted by PUA when update done/failed.
        if not os.path.exists(GRANULAR_LOG_FILE):
            logger.debug(f"File not exist. Creating the {GRANULAR_LOG_FILE}...")
            data: Dict[str, List[Any]] = {
                "UpdateLog": []
            }
            with open(GRANULAR_LOG_FILE, "w") as file:
                json.dump(data, file)
        if log:
            self.update_granular_with_log(log)
            return
        if self.ota_type == SOTA:
            if check_package:
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
        try:
            if log_data:
                # Get the latest upgrade history
                # Split the log into parts
                parts = log_data.split('\n\n')
                # Filter parts that contain 'upgrade'
                upgrade_parts = [part for part in parts if 'upgrade' in part.lower()]
                if upgrade_parts:
                    latest_upgrade = upgrade_parts[-1]
                else:
                    raise KeyError
                update_time = get_package_start_date(latest_upgrade)
                package_dict = extract_package_names_and_versions(latest_upgrade)

                # Load current data in granular log file.
                with open(GRANULAR_LOG_FILE, 'r') as f:
                    data = json.load(f)

                # Create the package information and store it
                for package_name, version in package_dict.items():
                    logger.debug(f"Package: {package_name}, Version: {version}")

                    # Get status using dpkg-query
                    status = check_package_status(package_name)

                    package_info = {
                        "update_type": OS,
                        "package_name": package_name,
                        "update_time": update_time,
                        "action": PACKAGE_UPGRADE,
                        "status": status,
                        "version": version
                    }
                    # Remove previous entries with the same package_name from the UpdateLog list
                    data['UpdateLog'] = [log for log in data['UpdateLog'] if
                                         log['package_name'] != package_info['package_name']]
                    # Append the new package information to the UpdateLog list
                    data['UpdateLog'].append(package_info)

                # Open the file in write mode to save the updated data
                with open(GRANULAR_LOG_FILE, 'w') as f:
                    json.dump(data, f, indent=4)
        except (IndexError, KeyError) as e:
            logger.info(f"No upgrade information found in history log. Error: {e}")

    def update_granular_with_sota_package_list_install(self) -> None:
        """This function checks the latest package installation information using dpkg-query command.
           It checks all the packages inside package_list and records the package's status and version.
           These information will be stored in granular log file.
        """
        # Load current data in granular log file.
        with open(GRANULAR_LOG_FILE, 'r') as f:
            data = json.load(f)

        packages = self.package_list.split(',')
        for package_name in packages:
            #  Get status
            status = check_package_status(package_name)

            # Get Version
            version = check_package_version(package_name)

            package_info = {
                "update_type": APPLICATION,
                "package_name": package_name,
                "update_time": self._time.isoformat(),
                "action": PACKAGE_INSTALL,
                "status": status,
                "version": version
            }

            # Remove previous entries with the same package_name from the UpdateLog list
            data['UpdateLog'] = [log for log in data['UpdateLog'] if
                                 log['package_name'] != package_info['package_name']]
            # Append the latest package information to the UpdateLog list
            data['UpdateLog'].append(package_info)

            # Open the file in write mode to save the updated data
            with open(GRANULAR_LOG_FILE, 'w') as f:
                json.dump(data, f, indent=4)

    def update_granular_with_log(self, log: dict) -> None:
        """This function stores the log provided into the granular log file."""
        logger.debug("")
        try:
            # Load current data in granular log file.
            with open(GRANULAR_LOG_FILE, 'r') as f:
                data = json.load(f)
            # Append the log to the UpdateLog
            data['UpdateLog'].append(log)

            # Open the file in write mode to save the updated data
            with open(GRANULAR_LOG_FILE, 'w') as f:
                json.dump(data, f, indent=4)
        except json.JSONDecodeError as err:
            logger.error(f"Error decoding JSON from {GRANULAR_LOG_FILE}: {err}")


    def read_history_log_file(self) -> Optional[str]:
        """Read the apt history log file.

        @return: content of the history log file
        """
        try:
            with open(SYSTEM_HISTORY_LOG_FILE, 'r') as log_file:
                return log_file.read()
        except (OSError, FileNotFoundError) as e:
            logger.error(f'Error in opening the file {SYSTEM_HISTORY_LOG_FILE}: {e}')
            return None
