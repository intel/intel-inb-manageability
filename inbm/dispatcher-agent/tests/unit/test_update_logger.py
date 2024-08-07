import datetime
import json
import os
from unittest import TestCase
from unittest.mock import patch

from dispatcher.update_logger import UpdateLogger
from inbm_lib.constants import LOG_FILE, OTA_PENDING, OTA_SUCCESS, FAIL, FORMAT_VERSION, GRANULAR_LOG_FILE, \
    SYSTEM_HISTORY_LOG_FILE, PACKAGE_SUCCESS

SOTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd></sota></type></ota></manifest>'


class TestUpdateLogger(TestCase):

    def setUp(self) -> None:
        self.update_logger = UpdateLogger(ota_type="sota", data=SOTA_MANIFEST)

    def tearDown(self) -> None:
        # Ensure the GRANULAR_LOG_FILE always removed after the test case
        if os.path.exists(GRANULAR_LOG_FILE):
            os.remove(GRANULAR_LOG_FILE)

    def test_set_time(self) -> None:
        ori_time = self.update_logger._time
        self.update_logger.set_time()
        self.assertNotEqual(ori_time, self.update_logger._time)

    @patch('dispatcher.update_logger.UpdateLogger.write_log_file')
    def test_save_log(self, mock_write_log_file) -> None:
        expected_status = FAIL
        self.update_logger._time = datetime.datetime(2023, 12, 25, 00, 00, 00, 000000)
        expected_error = '{"status": 302, "message": "OTA FAILURE"}'
        expected_metadata = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>ota</type><ota><header><type>aota</type><repo>remote</repo></header><type><aota name="application-update"><cmd>update</cmd><app>application</app><fetch>http://security.ubuntu.com/ubuntu/pool/main/n/net-tools/net-tools_1.60-25ubuntu2.1_amd64.deb</fetch><deviceReboot>no</deviceReboot></aota></type></ota></manifest>'
        expected_type = "aota"
        self.update_logger.status = expected_status
        self.update_logger.error = expected_error
        self.update_logger.metadata = expected_metadata
        self.update_logger.ota_type = expected_type

        self.update_logger.save_log()

        expected_log = r'{"Status": "FAIL", "Type": "aota", "Time": "2023-12-25 00:00:00", "Metadata": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><manifest><type>ota</type><ota><header><type>aota</type><repo>remote</repo></header><type><aota name=\"application-update\"><cmd>update</cmd><app>application</app><fetch>http://security.ubuntu.com/ubuntu/pool/main/n/net-tools/net-tools_1.60-25ubuntu2.1_amd64.deb</fetch><deviceReboot>no</deviceReboot></aota></type></ota></manifest>", "Error": "{\"status\": 302, \"message\": \"OTA FAILURE\"}", "Version": "v1"}'

        mock_write_log_file.assert_called_once_with(expected_log)

    @patch('dispatcher.update_logger.UpdateLogger.read_log_file')
    @patch('dispatcher.update_logger.UpdateLogger.write_log_file')
    def test_update_log(self, mock_write_log_file, mock_read_log_file) -> None:
        expected_type = "sota"
        self.update_logger._time = datetime.datetime(2023, 12, 25, 00, 00, 00, 000000)
        self.update_logger.ota_type = expected_type
        self.update_logger.status = OTA_PENDING
        self.update_logger.error = ""

        pending_log = {'Status': OTA_PENDING,
                       'Type': expected_type,
                       'Time': datetime.datetime(2023, 12, 25, 00, 00, 00, 000000).strftime("%Y-%m-%d %H:%M:%S"),
                       'Metadata': SOTA_MANIFEST,
                       'Error': '',
                       'Version': FORMAT_VERSION}

        mock_read_log_file.return_value = json.dumps(pending_log)

        self.update_logger.update_log(status=OTA_SUCCESS)

        expected_log = r'{"Status": "SUCCESS", "Type": "sota", "Time": "2023-12-25 00:00:00", "Metadata": "<?xml version=\"1.0\" encoding=\"utf-8\"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile=\"y\">update</cmd></sota></type></ota></manifest>", "Error": "", "Version": "v1"}'

        mock_write_log_file.assert_called_once_with(expected_log)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("install ok installed", "", 0))
    def test_save_granular_log_file_sota_without_package_list(self, mock_status) -> None:
        self.update_logger.ota_type = "sota"

        history_content = """
        Start-Date: 2024-07-03  19:28:53
        Commandline: /bin/apt-get -yq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade
        Upgrade: terraform:amd64 (1.9.0-1, 1.9.1-1)
        End-Date: 2024-07-03  19:28:53
        """

        expected_content = {
                            "UpdateLog": [
                                    {
                                        "update_type": "os",
                                        "package_name": "terraform:amd64",
                                        "update_time": "2024-07-03T19:28:53",
                                        "action": "upgrade",
                                        "status": "SUCCESS",
                                        "version": "1.9.0-1, 1.9.1-1"
                                    }
                                ]
                            }

        with open(SYSTEM_HISTORY_LOG_FILE, "w") as file:
            file.write(history_content)

        self.update_logger.save_granular_log_file()

        with open(GRANULAR_LOG_FILE, 'r') as f:
            granular_log = json.load(f)

        mock_status.assert_called_once()
        self.assertEqual(granular_log, expected_content)

    def test_save_granular_log_file_sota_without_package_list_without_upgrade_but_with_upgrade_keyword_in_text(self) -> None:
        self.update_logger.ota_type = "sota"

        history_content = """
        Start-Date: 2024-08-06  06:26:14
        Commandline: apt remove -y unattended-upgrades
        Remove: unattended-upgrades:amd64 (2.8ubuntu1)
        End-Date: 2024-08-06  06:26:14
        
        Start-Date: 2024-08-06  07:45:30
        Commandline: /bin/apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --no-download --fix-missing -yq install intel-opencl-icd
        Install: intel-opencl-icd:amd64 (22.14.22890-1)
        End-Date: 2024-08-06  07:45:30
        
        Start-Date: 2024-08-06  08:12:35
        Commandline: /bin/apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --no-download --fix-missing -yq install mongodb-org
        Install: mongodb-mongosh:amd64 (2.2.15, automatic), mongodb-org-database-tools-extra:amd64 (7.0.12, automatic), mongodb-org-shell:amd64 (7.0.12, automatic), mongodb-org-database:amd64 (7.0.12, automatic), mongodb-org-server:amd64 (7.0.12, automatic), mongodb-org:amd64 (7.0.12), mongodb-org-tools:amd64 (7.0.12, automatic), mongodb-database-tools:amd64 (100.10.0, automatic), mongodb-org-mongos:amd64 (7.0.12, automatic)
        End-Date: 2024-08-06  08:12:42
        """

        expected_content: dict = {
                            "UpdateLog": [
                                ]
                            }

        with open(SYSTEM_HISTORY_LOG_FILE, "w") as file:
            file.write(history_content)

        self.update_logger.save_granular_log_file()

        with open(GRANULAR_LOG_FILE, 'r') as f:
            granular_log = json.load(f)

        self.assertEqual(granular_log, expected_content)

    def test_save_granular_log_file_sota_without_package_list_without_update_keyword(self) -> None:
        self.update_logger.ota_type = "sota"

        history_content = """
        Start-Date: 2024-08-06  07:45:30
        Commandline: /bin/apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --no-download --fix-missing -yq install intel-opencl-icd
        Install: intel-opencl-icd:amd64 (22.14.22890-1)
        End-Date: 2024-08-06  07:45:30

        Start-Date: 2024-08-06  08:12:35
        Commandline: /bin/apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --no-download --fix-missing -yq install mongodb-org
        Install: mongodb-mongosh:amd64 (2.2.15, automatic), mongodb-org-database-tools-extra:amd64 (7.0.12, automatic), mongodb-org-shell:amd64 (7.0.12, automatic), mongodb-org-database:amd64 (7.0.12, automatic), mongodb-org-server:amd64 (7.0.12, automatic), mongodb-org:amd64 (7.0.12), mongodb-org-tools:amd64 (7.0.12, automatic), mongodb-database-tools:amd64 (100.10.0, automatic), mongodb-org-mongos:amd64 (7.0.12, automatic)
        End-Date: 2024-08-06  08:12:42
        """

        expected_content: dict = {
            "UpdateLog": [
            ]
        }

        with open(SYSTEM_HISTORY_LOG_FILE, "w") as file:
            file.write(history_content)

        self.update_logger.save_granular_log_file()

        with open(GRANULAR_LOG_FILE, 'r') as f:
            granular_log = json.load(f)

        self.assertEqual(granular_log, expected_content)

    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', side_effect=[("install ok installed", "", 0),
                                                                              ("1:26.3+1-1ubuntu2", "", 0)])
    def test_save_granular_log_file_sota_with_package_list(self, mock_run) -> None:
        self.update_logger.ota_type = "sota"
        self.update_logger._time = datetime.datetime(2024, 7, 3, 1, 50, 55, 935223)
        self.update_logger.package_list = "emacs"
        expected_content = {
                            "UpdateLog": [
                                    {
                                        "update_type": "application",
                                        "package_name": "emacs",
                                        "update_time": "2024-07-03T01:50:55.935223",
                                        "action": "install",
                                        "status": "SUCCESS",
                                        "version": "1:26.3+1-1ubuntu2"
                                    }
                                ]
                            }

        self.update_logger.save_granular_log_file()

        with open(GRANULAR_LOG_FILE, 'r') as f:
            granular_log = json.load(f)

        assert mock_run.call_count == 2
        self.assertEqual(granular_log, expected_content)
