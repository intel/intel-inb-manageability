import unittest
from unittest.mock import Mock
import os
import threading
from time import sleep
from inbm_lib.xmlhandler import XmlHandler

from dispatcher.sota.cancel import cancel_thread, is_active_ota_sota_download_only
from dispatcher.common.result_constants import Result, CODE_OK, CODE_BAD_REQUEST

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestCancelThread(unittest.TestCase):

    def test_cancel_thread_success(self) -> None:
        def mock_thread(cancel_event: threading.Event):
            while not cancel_event.is_set():
                sleep(3)

        sota_cancel_manifest = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
        <type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd>
        <mode>cancel</mode><package_list></package_list><deviceReboot>yes</deviceReboot>
        </sota></type></ota></manifest> """

        cancel_event = threading.Event()

        type_of_manifest = "ota"
        thread_list = []
        worker = threading.Thread(target=mock_thread, args=(cancel_event,))
        worker.setDaemon(True)
        thread_list.append(worker)
        worker.start()
        sleep(1)
        parsed_head = XmlHandler(sota_cancel_manifest, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

        sota_download_only_manifest = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
        <type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd>
        <mode>download-only</mode><package_list></package_list><deviceReboot>yes</deviceReboot>
        </sota></type></ota></manifest> """
        active_parsed_head = XmlHandler(sota_download_only_manifest, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

        self.assertTrue(cancel_thread(type_of_manifest=type_of_manifest,
                                      parsed_head=parsed_head,
                                      thread_list=thread_list,
                                      type_of_active_manifest=type_of_manifest,
                                      active_thread_parsed_head=active_parsed_head,
                                      dispatcher_broker=Mock(),
                                      cancel_event=cancel_event))

    def test_cancel_thread_with_thread_running_with_no_download_mode(self) -> None:
        def mock_thread(cancel_event: threading.Event):
            while not cancel_event.is_set():
                sleep(3)

        sota_cancel_manifest = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
        <type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd>
        <mode>cancel</mode><package_list></package_list><deviceReboot>yes</deviceReboot>
        </sota></type></ota></manifest> """

        cancel_event = threading.Event()

        type_of_manifest = "ota"
        thread_list = []
        worker = threading.Thread(target=mock_thread, args=(cancel_event,))
        worker.setDaemon(True)
        thread_list.append(worker)
        worker.start()
        sleep(1)
        parsed_head = XmlHandler(sota_cancel_manifest, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

        sota_no_download_manifest = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
        <type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd>
        <mode>no-download</mode><package_list></package_list><deviceReboot>yes</deviceReboot>
        </sota></type></ota></manifest> """
        active_parsed_head = XmlHandler(sota_no_download_manifest, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        dispatcher_broker = Mock()
        self.assertTrue(cancel_thread(type_of_manifest=type_of_manifest,
                                      parsed_head=parsed_head,
                                      thread_list=thread_list,
                                      type_of_active_manifest=type_of_manifest,
                                      active_thread_parsed_head=active_parsed_head,
                                      dispatcher_broker=dispatcher_broker,
                                      cancel_event=cancel_event))

        dispatcher_broker.send_result.assert_called_once_with(str(Result(CODE_BAD_REQUEST,
                                                              "Current thread is not SOTA download-only. "
                                                              "Cannot proceed with the cancel request.")))

    def test_cancel_thread_without_running_thread_manifest(self) -> None:
        def mock_thread(cancel_event: threading.Event):
            while not cancel_event.is_set():
                sleep(3)

        sota_cancel_manifest = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
        <type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd>
        <mode>cancel</mode><package_list></package_list><deviceReboot>yes</deviceReboot>
        </sota></type></ota></manifest> """

        cancel_event = threading.Event()

        type_of_manifest = "ota"
        thread_list = []
        worker = threading.Thread(target=mock_thread, args=(cancel_event,))
        worker.setDaemon(True)
        thread_list.append(worker)
        worker.start()
        sleep(1)
        parsed_head = XmlHandler(sota_cancel_manifest, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

        dispatcher_broker = Mock()
        self.assertTrue(cancel_thread(type_of_manifest=type_of_manifest,
                                      parsed_head=parsed_head,
                                      thread_list=thread_list,
                                      type_of_active_manifest=type_of_manifest,
                                      active_thread_parsed_head=None,
                                      dispatcher_broker=dispatcher_broker,
                                      cancel_event=cancel_event))

        dispatcher_broker.send_result.assert_called_once_with(str(Result(CODE_BAD_REQUEST, "Running thread manifest not found.")))

    def test_is_active_ota_sota_download_only_return_true(self) -> None:

        sota_download_only_manifest = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
        <type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd>
        <mode>download-only</mode><package_list></package_list><deviceReboot>yes</deviceReboot>
        </sota></type></ota></manifest> """

        type_of_manifest = "ota"
        parsed_head = XmlHandler(sota_download_only_manifest, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

        self.assertTrue(is_active_ota_sota_download_only(type_of_manifest, parsed_head))

    def test_is_active_ota_sota_download_only_return_false(self) -> None:

        sota_download_only_manifest = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
        <type>sota</type><repo>remote</repo></header><type><sota><cmd logtofile="y">update</cmd>
        <mode>no-download</mode><package_list></package_list><deviceReboot>yes</deviceReboot>
        </sota></type></ota></manifest> """

        type_of_manifest = "ota"
        parsed_head = XmlHandler(sota_download_only_manifest, is_file=False, schema_location=TEST_SCHEMA_LOCATION)

        self.assertFalse(is_active_ota_sota_download_only(type_of_manifest, parsed_head))
