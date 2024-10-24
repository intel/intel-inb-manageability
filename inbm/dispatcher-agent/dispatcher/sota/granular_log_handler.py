"""
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import threading

from inbm_common_lib.utility import get_os_version
from inbm_lib.detect_os import detect_os, LinuxDistType
from inbm_lib.constants import OTA_PENDING, FAIL, OTA_SUCCESS, ROLLBACK, GRANULAR_LOG_FILE

from ..update_logger import UpdateLogger

logger = logging.getLogger(__name__)

class GranularLogHandler:
    def __init__(self) -> None:
        self._granular_lock = threading.Lock()

    def save_granular_log(self, update_logger: UpdateLogger, check_package: bool = True) -> None:
        """Save the granular log.
        In Ubuntu, it saves the package level information.
        In TiberOS, it saves the detail of the SOTA update.

        @param check_package: True if you want to check the package's status and version and record them in Ubuntu.
        """
        log = {}
        current_os = detect_os()
        # TODO: Remove Mariner when confirmed that TiberOS is in use
        with self._granular_lock:
            if current_os == LinuxDistType.tiber.name or current_os == LinuxDistType.Mariner.name:
                # Delete the previous log if exist.
                if os.path.exists(GRANULAR_LOG_FILE):
                    with open(GRANULAR_LOG_FILE, "r+") as file:
                        file.truncate(0)

                if update_logger.detail_status == FAIL or update_logger.detail_status == ROLLBACK:
                    log = {
                        "StatusDetail.Status": update_logger.detail_status,
                        "FailureReason": update_logger.error
                    }
                elif update_logger.detail_status == OTA_SUCCESS or update_logger.detail_status == OTA_PENDING:
                    log = {
                        "StatusDetail.Status": update_logger.detail_status,
                        "Version": get_os_version()
                    }
                # In TiberOS, no package level information needed.
                update_logger.save_granular_log_file(log=log, check_package=False)
            else:
                update_logger.save_granular_log_file(check_package=check_package)
