"""
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from typing import List
import logging
import os
import threading

from inbm_common_lib.utility import get_image_build_date
from inbm_lib.detect_os import detect_os, LinuxDistType
from inbm_lib.constants import OTA_PENDING, FAIL, OTA_SUCCESS, ROLLBACK, GRANULAR_LOG_FILE
from .constants import *

from ..update_logger import UpdateLogger

logger = logging.getLogger(__name__)

class GranularLogHandler:
    def __init__(self) -> None:
        self._granular_lock = threading.Lock()

    def save_granular_log(self, update_logger: UpdateLogger, check_package: bool = True) -> None:
        """Save the granular log.
        In Ubuntu, it saves the package level information.
        In Tiber, it saves the detail of the SOTA update.

        @param check_package: True if you want to check the package's status and version and record them in Ubuntu.
        """
        log = {}
        current_os = detect_os()
        with self._granular_lock:
            if LinuxDistType.Microvisor.name in current_os.lower():
                # Delete the previous log if exist.
                if os.path.exists(GRANULAR_LOG_FILE):
                    with open(GRANULAR_LOG_FILE, "r+") as file:
                        file.truncate(0)

                if update_logger.detail_status == FAIL or update_logger.detail_status == ROLLBACK:
                    # TODO: Can add text field here for error message
                    log = {
                        "StatusDetail.Status": update_logger.detail_status,
                        "FailureReason": self.map_failure_reason(update_logger.error)
                    }
                elif update_logger.detail_status == OTA_SUCCESS or update_logger.detail_status == OTA_PENDING:
                    log = {
                        "StatusDetail.Status": update_logger.detail_status,
                        "Version": get_image_build_date()
                    }
                # In EMT, no package level information needed.
                update_logger.save_granular_log_file(log=log, check_package=False)
            else:
                update_logger.save_granular_log_file(check_package=check_package)

    def map_failure_reason(self, error_log: str) -> str:
        """ This method parses the error log to map the enum of failure reasons as required by MM.
        It is only used for Edge Microvisor Toolkit.

        @param error_log: Error message to be checked
        @return: Corresponding mapping of the failure reason
        """
        logger.debug("")
        if self.search_keyword(error_log, [UT_WRITE_ERROR]):
            return FAILURE_REASON_UT_WRITE

        if self.search_keyword(error_log, [UT_BOOT_CONFIGURATION_ERROR]):
            return FAILURE_REASON_UT_BOOT_CONFIGURATION

        if self.search_keyword(error_log, [UT_OS_COMMIT_ERROR]):
            return FAILURE_REASON_OS_COMMIT

        if self.search_keyword(error_log, DOWNLOAD_ERROR_LIST):
            return FAILURE_REASON_DOWNLOAD

        if self.search_keyword(error_log, INSUFFICIENT_STORAGE_ERROR_LIST):
            return FAILURE_REASON_INSUFFICIENT_STORAGE

        if self.search_keyword(error_log, RS_AUTHENTICATION_ERROR_LIST):
            return FAILURE_REASON_RS_AUTHENTICATION

        if self.search_keyword(error_log, SIGNATURE_CHECK_ERROR_LIST):
            return FAILURE_REASON_SIGNATURE_CHECK

        if self.search_keyword(error_log, BOOTLOADER_ERROR_LIST):
            return FAILURE_REASON_BOOTLOADER

        if self.search_keyword(error_log, [CRITICAL_SERVICES_ERROR]):
            return FAILURE_REASON_CRITICAL_SERVICES

        # Can source verification error considered as inbm failure?
        if self.search_keyword(error_log, INBM_ERROR_LIST):
            return FAILURE_REASON_INBM

        # Other error returns as unspecified
        return FAILURE_REASON_UNSPECIFIED

    def search_keyword(self, log: str, words: List[str]) -> bool:
        """Checks if the desired keywords exist in the log.

        @param log: Error message to be checked
        @param words: expected keywords in the message
        @return: True if keyword found, False if keyword not found in message
        """
        for word in words:
            if log.find(word) >= 0:
                return True
        return False