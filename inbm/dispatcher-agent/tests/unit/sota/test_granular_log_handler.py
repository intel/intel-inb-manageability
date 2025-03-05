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
    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('dispatcher.sota.granular_log_handler.get_image_build_date', return_value='20241026100955')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_success_log(self, mock_run, mock_get_image_build_date, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = OTA_SUCCESS

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": OTA_SUCCESS,
                    "Version": '20241026100955'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)


    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('dispatcher.sota.granular_log_handler.get_image_build_date', return_value='20241026100955')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_pending_log(self, mock_run, mock_get_image_build_date, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = OTA_PENDING

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": OTA_PENDING,
                    "Version": '20241026100955'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_fail_log(self, mock_run, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = FAIL
        update_logger.error = 'Error getting artifact size from https://registry-rs.internal.ledgepark.intel.com/v2/one-intel-edge/tiber/manifests/latest using token'

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": FAIL,
                    "FailureReason": 'download'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)


    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_rollback_log(self, mock_run, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = ROLLBACK
        update_logger.error = 'FAILED INSTALL: System has not been properly updated; reverting..'
        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": ROLLBACK,
                    "FailureReason": 'bootloader'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)


    @patch('os.path.exists', side_effect=[True, False])
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('dispatcher.sota.granular_log_handler.get_image_build_date', return_value='20241026100955')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_truncate_file_being_called(self, mock_run, mock_get_image_build_date, mock_load, mock_dump, mock_exists) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = OTA_SUCCESS

        with patch('builtins.open', mock_open()) as m_open:
            mock_file = m_open.return_value.__enter__.return_value
            mock_file.truncate.return_value = None
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)
            mock_file.truncate.assert_called_once()

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": OTA_SUCCESS,
                    "Version": '20241026100955'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_insufficient_storage_fail_log(self, mock_run, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = FAIL
        update_logger.error = 'Insufficient free space'

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": FAIL,
                    "FailureReason": 'insufficientstorage'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_ut_write_fail_log(self, mock_run, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = FAIL
        update_logger.error = 'Command: /usr/bin/os-update-tool.sh -w -u /var/cache/manageability/repository-tool/sota/tiber-readonly-1.0.20241120.0715.raw.gz  status: Failed  errors: '

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": FAIL,
                    "FailureReason": 'utwrite'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_ut_apply_fail_log(self, mock_run, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = FAIL
        update_logger.error = 'Command: /usr/bin/os-update-tool.sh -a  status: Failed  errors: '

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": FAIL,
                    "FailureReason": 'utbootconfiguration'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_ut_commit_fail_log(self, mock_run, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = FAIL
        update_logger.error = 'FAILED INSTALL: System has not been properly updated; reverting.. Error: Failed to run UT commit command /usr/bin/os-update-tool.sh -c . Error:'

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": FAIL,
                    "FailureReason": 'oscommit'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_rsauthentication_fail_log(self, mock_run, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = FAIL
        update_logger.error = 'Failed to access URI:Status code for https://files-rs.internal.ledgepark.intel.com/repository/Tiber/Tiber-nonRT/tiber-readonly-1.0.20241120.0715.raw.gz is 0. Invalid URI or Token might be expired.'

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": FAIL,
                    "FailureReason": 'rsauthentication'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_signature_check_fail_log(self, mock_run, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = FAIL
        update_logger.error = 'Signature checks failed'

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": FAIL,
                    "FailureReason": 'signaturecheck'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

    @patch('typing.IO.truncate')
    @patch('os.path.exists', return_value=False)
    @patch('json.dump')
    @patch('json.load', return_value={"UpdateLog":[]})
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
    def test_save_granular_in_tiber_with_critical_service_fail_log(self, mock_run, mock_load, mock_dump, mock_exists, mock_truncate) -> None:
        update_logger = UpdateLogger("SOTA", "metadata")
        update_logger.detail_status = FAIL
        update_logger.error = 'Critical service failure'

        with patch('builtins.open', mock_open()) as m_open:
            GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

        expected_content = {
            "UpdateLog": [
                {
                    "StatusDetail.Status": FAIL,
                    "FailureReason": 'criticalservices'
                }
            ]
        }

        mock_dump.assert_called_with(expected_content, m_open(), indent=4)

        @patch('typing.IO.truncate')
        @patch('os.path.exists', return_value=False)
        @patch('json.dump')
        @patch('json.load', return_value={"UpdateLog": []})
        @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
        def test_save_granular_in_tiber_with_trusted_repository_fail_log(self, mock_run, mock_load, mock_dump,
                                                                         mock_exists, mock_truncate) -> None:
            update_logger = UpdateLogger("SOTA", "metadata")
            update_logger.detail_status = FAIL
            update_logger.error = 'Source verification failed.  Source is not in the trusted repository.'

            with patch('builtins.open', mock_open()) as m_open:
                GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

            expected_content = {
                "UpdateLog": [
                    {
                        "StatusDetail.Status": FAIL,
                        "FailureReason": 'inbm'
                    }
                ]
            }

            mock_dump.assert_called_with(expected_content, m_open(), indent=4)

        @patch('typing.IO.truncate')
        @patch('os.path.exists', return_value=False)
        @patch('json.dump')
        @patch('json.load', return_value={"UpdateLog": []})
        @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("tiber", "", 0))
        def test_save_granular_in_tiber_with_unspecified_fail_log(self, mock_run, mock_load, mock_dump,
                                                                         mock_exists, mock_truncate) -> None:
            update_logger = UpdateLogger("SOTA", "metadata")
            update_logger.detail_status = FAIL
            update_logger.error = 'An unexpected error happens.'

            with patch('builtins.open', mock_open()) as m_open:
                GranularLogHandler().save_granular_log(update_logger=update_logger, check_package=False)

            expected_content = {
                "UpdateLog": [
                    {
                        "StatusDetail.Status": FAIL,
                        "FailureReason": 'unspecified'
                    }
                ]
            }

            mock_dump.assert_called_with(expected_content, m_open(), indent=4)


