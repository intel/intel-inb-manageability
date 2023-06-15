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

    def __init__(self, ota_type: str, data: str) -> None:
        self.status = ""
        self.ota_type = ota_type
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
