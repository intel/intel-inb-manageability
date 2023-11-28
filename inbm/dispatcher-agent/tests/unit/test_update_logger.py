import datetime
import json
from unittest import TestCase
from unittest.mock import patch

from dispatcher.update_logger import UpdateLogger
from inbm_lib.constants import LOG_FILE, OTA_PENDING, OTA_SUCCESS, OTA_FAIL, FORMAT_VERSION
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_CACHE_PATH_PREFIX

SOTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd></sota></type></ota></manifest>'


class TestUpdateLogger(TestCase):

    def setUp(self) -> None:
        self.update_logger = UpdateLogger(ota_type="sota", data=SOTA_MANIFEST)

    def test_set_time(self) -> None:
        ori_time = self.update_logger._time
        self.update_logger.set_time()
        self.assertNotEqual(ori_time, self.update_logger._time)

    @patch('dispatcher.update_logger.UpdateLogger.write_log_file')
    def test_save_log(self, mock_write_log_file) -> None:
        expected_status = OTA_FAIL
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
