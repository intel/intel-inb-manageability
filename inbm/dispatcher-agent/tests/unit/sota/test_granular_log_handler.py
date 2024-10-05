"""
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import testtools
from unittest.mock import patch, mock_open

from dispatcher.sota.granular_log_handler import GranularLogHandler
from dispatcher.update_logger import UpdateLogger
from inbm_lib.constants import OTA_SUCCESS, OTA_PENDING, FAIL, ROLLBACK

class TestGranularLogHandler(testtools.TestCase):
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('dispatcher.sota.granular_log_handler.get_os_version', return_value='2.0.20240802.0213')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiberos_with_success_log(self, mock_run, mock_get_os_version, mock_load, mock_dump) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = OTA_SUCCESS

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": OTA_SUCCESS,
                    "Version": '2.0.20240802.0213'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)


    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('dispatcher.sota.granular_log_handler.get_os_version', return_value='2.0.20240802.0213')    
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiberos_with_pending_log(self, mock_run, mock_get_os_version, mock_load, mock_dump) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = OTA_PENDING

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": OTA_PENDING,
                    "Version": '2.0.20240802.0213'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiberos_with_fail_log(self, mock_run, mock_load, mock_dump) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = FAIL
        update_logger.error = 'Error getting artifact size from https://registry-rs.internal.ledgepark.intel.com/v2/one-intel-edge/tiberos/manifests/latest using token'

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": FAIL,
                    "FailureReason": 'Error getting artifact size from https://registry-rs.internal.ledgepark.intel.com/v2/one-intel-edge/tiberos/manifests/latest using token'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)


    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiberos_with_rollback_log(self, mock_run, mock_load, mock_dump) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = ROLLBACK
        update_logger.error = 'FAILED INSTALL: System has not been properly updated; reverting..'
        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": ROLLBACK,
                    "FailureReason": 'FAILED INSTALL: System has not been properly updated; reverting..'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)