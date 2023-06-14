import datetime
import json
import os
from unittest import TestCase

from dispatcher.update_logger import UpdateLogger
from inbm_lib.constants import LOG_FILE, OTA_PENDING, OTA_SUCCESS, OTA_FAIL, FORMAT_VERSION
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_CACHE_PATH_PREFIX


SOTA_MANIFEST = '<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd></sota></type></ota></manifest>'


class TestUpdateLogger(TestCase):

    def setUp(self):
        self.update_logger = UpdateLogger(ota_type="sota", data=SOTA_MANIFEST)

    def test_set_time(self):
        ori_time = self.update_logger._time
        self.update_logger.set_time()
        self.assertNotEquals(ori_time, self.update_logger._time)

    def test_set_status_and_error(self):
        expected_status = OTA_FAIL
        expected_error = '{"status": 302, "message": "OTA FAILURE"}'
        self.update_logger.set_status_and_error(status=expected_status, err=expected_error)
        self.assertEquals(expected_status, self.update_logger._status)
        self.assertEquals(expected_error, self.update_logger._error)

    def test_set_metadata(self):
        expected_metadata = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>ota</type><ota><header><type>aota</type><repo>remote</repo></header><type><aota name="application-update"><cmd>update</cmd><app>application</app><fetch>http://security.ubuntu.com/ubuntu/pool/main/n/net-tools/net-tools_1.60-25ubuntu2.1_amd64.deb</fetch><deviceReboot>no</deviceReboot></aota></type></ota></manifest>'
        self.update_logger.set_metadata(data=expected_metadata)
        self.assertEquals(expected_metadata, self.update_logger._meta_data)

    def test_set_ota_type(self):
        expected_type = "aota"
        self.update_logger.set_ota_type(expected_type)
        self.assertEquals(expected_type, self.update_logger.ota_type)

    def test_save_log(self):
        expected_status = OTA_FAIL
        self.update_logger._time = datetime.datetime(2023, 12, 25, 00, 00, 00, 000000)
        expected_error = '{"status": 302, "message": "OTA FAILURE"}'
        expected_metadata = '<?xml version="1.0" encoding="UTF-8"?><manifest><type>ota</type><ota><header><type>aota</type><repo>remote</repo></header><type><aota name="application-update"><cmd>update</cmd><app>application</app><fetch>http://security.ubuntu.com/ubuntu/pool/main/n/net-tools/net-tools_1.60-25ubuntu2.1_amd64.deb</fetch><deviceReboot>no</deviceReboot></aota></type></ota></manifest>'
        expected_type = "aota"
        self.update_logger.set_status_and_error(status=expected_status, err=expected_error)
        self.update_logger.set_metadata(data=expected_metadata)
        self.update_logger.set_ota_type(expected_type)

        if not os.path.exists(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX):
            os.makedirs(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX)
        self.update_logger.save_log()

        expected_log = {'Status': OTA_FAIL,
                        'Type': expected_type,
                        'Time': datetime.datetime(2023, 12, 25, 00, 00, 00, 000000).strftime("%Y-%m-%d %H:%M:%S"),
                        'Metadata': expected_metadata,
                        'Error': expected_error,
                        'Version': FORMAT_VERSION}

        with open(LOG_FILE, 'r') as log_file:
            log = log_file.read()

        self.assertEquals(json.dumps(str(expected_log)), log)

    def test_update_log(self):
        expected_type = "sota"
        self.update_logger._time = datetime.datetime(2023, 12, 25, 00, 00, 00, 000000)
        self.update_logger.set_ota_type(expected_type)
        self.update_logger.set_status_and_error(status=OTA_PENDING, err="")
        if not os.path.exists(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX):
            os.makedirs(INTEL_MANAGEABILITY_CACHE_PATH_PREFIX)
        self.update_logger.save_log()
        self.update_logger.update_log(status=OTA_SUCCESS)

        expected_log = {'Status': OTA_SUCCESS,
                        'Type': expected_type,
                        'Time': datetime.datetime(2023, 12, 25, 00, 00, 00, 000000).strftime("%Y-%m-%d %H:%M:%S"),
                        'Metadata': SOTA_MANIFEST,
                        'Error': '',
                        'Version': FORMAT_VERSION}

        with open(LOG_FILE, 'r') as log_file:
            log = log_file.read()

        self.assertEquals(json.dumps(str(expected_log)), log)
