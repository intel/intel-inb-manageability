import unittest
from unittest.mock import patch, Mock
import os
import threading
from time import sleep
from inbm_lib.xmlhandler import XmlHandler

from dispatcher.sota.cancel import cancel_thread

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestCancelThread(unittest.TestCase):

    @patch('signal.pthread_kill')
    def test_cancel_thread_success(self, mock_kill) -> None:
        # We can't send the signal to kill the thread here. The signal will be sent to unit test main thread.
        def mock_thread():
            sleep(10)

        sota_cancel_manifest = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
        <type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd>
        <mode>cancel</mode><package_list></package_list><deviceReboot>yes</deviceReboot>
        </sota></type></ota></manifest> """

        type_of_manifest = "ota"
        thread_list = []

        worker = threading.Thread(target=mock_thread)
        worker.setDaemon(True)
        thread_list.append(worker)
        worker.start()
        sleep(1)
        parsed_head = XmlHandler(sota_cancel_manifest, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

        self.assertTrue(cancel_thread(type_of_manifest, parsed_head, thread_list))
        mock_kill.assert_called_once()
