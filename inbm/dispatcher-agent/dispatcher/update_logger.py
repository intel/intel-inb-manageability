"""
    Class for creating UpdateLogger objects to record OTA update status

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import json
import datetime
import logging
from typing import Optional

from inbm_lib.constants import LOG_FILE, OTA_PENDING, FORMAT_VERSION

logger = logging.getLogger(__name__)


class UpdateLogger:
    """UpdateLogger class stores the OTA update information and generates
       log file.
    @param ota_type: Type of OTA
    @param data: meta-data of the OTA
    """

    def __init__(self, ota_type: Optional[str], data: Optional[str]) -> None:
        self._status = ""
        self.ota_type = ota_type
        self._time = datetime.datetime.now()
        self._meta_data = data
        self._error: Optional[str] = None

    def set_time(self) -> None:
        """Set the OTA starting time."""
        self._time = datetime.datetime.now()

    def set_status_and_error(self, status: str, err: Optional[str]) -> None:
        """Set status and error message.

        @param status: status to be set.
        @param err:  error message to be set
        """
        self._status = status
        self._error = err

    def set_metadata(self, data: str) -> None:
        """Set metadata.

        @param data: metadata to be set (xml manifest)
        """
        self._meta_data = data

    def set_ota_type(self, ota_type: str) -> None:
        """Set ota type.

        @param ota_type: type of OTA to be set
        """
        self.ota_type = ota_type

    def save_log(self) -> None:
        """Save the log to a log file."""
        log = {'Status': self._status,
               'Type': self.ota_type,
               'Time': self._time.strftime("%Y-%m-%d %H:%M:%S"),
               'Metadata': self._meta_data,
               'Error': self._error,
               'Version': FORMAT_VERSION}

        try:
            with open(LOG_FILE, 'w') as log_file:
                log_file.write(json.dumps(str(log)))
        except OSError as e:
            logger.error(f'Error {e} on writing the file {LOG_FILE}')

    def update_log(self, status: str) -> None:
        """Update the log file after OTA reboot.
        If dispatcher state file check is passing, the status changes to SUCCESS.
        If dispatcher state file check is failing, the status changes to FAIL.

        @param status: status to be set
        """
        log = ""
        try:
            with open(LOG_FILE, 'r') as log_file:
                log = log_file.read()
            log = log.replace(OTA_PENDING, status)
            with open(LOG_FILE, 'w') as log_file:
                log_file.write(log)
        except OSError as e:
            logger.error(f'Error {e} on opening the file {LOG_FILE}')
