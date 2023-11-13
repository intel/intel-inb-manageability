import os
import tempfile
import unittest

import fixtures
from ..common.mock_resources import *
from mock import patch, mock_open
from dispatcher.sota.os_factory import SotaOsFactory
from dispatcher.sota.setup_helper import DebianBasedSetupHelper


class TestSetupHelper(unittest.TestCase):

    @patch('dispatcher.sota.setup_helper.DebianBasedSetupHelper.update_sources')
    def test_ubuntu_update_config(self, mock_apt_source):
        setup_helper = DebianBasedSetupHelper(None)  # type: ignore
        setup_helper.update_sources('')
        mock_apt_source.assert_called_once()

    @patch("pickle.load", return_value={'restart_reason': 'rollback', 'snapshot_num': 1})
    def test_ubuntu_extract_snap_num_from_disk(self, mock_pickle):
        with patch('builtins.open', new_callable=mock_open()) as m:
            setup_helper = DebianBasedSetupHelper(None)  # type: ignore
            setup_helper.extract_snap_num_from_disk()
            mock_pickle.assert_called_once()

    def test_ubuntu_update_apt_sources_fixtures(self):

        def setup_function():
            fd = tempfile.NamedTemporaryFile(prefix="sotatest", delete=False, mode="w+")
            for each in mock_apt_sources_list:
                fd.write(each)
            return fd.name

        def teardown_function(fixture):
            (fixture)

        fixture = fixtures.FunctionFixture(setup_function, teardown_function)
        fixture.setUp()
        payload = "dispatcher: http://testsuccess \n\t"

        setup_helper = DebianBasedSetupHelper(None)
        setup_helper.update_sources(payload, filename=fixture.fn_result)

        c = ""
        with open(fixture.fn_result) as f:
            for line in f:
                c += line

        self.assertEqual(mock_apt_expected, c)
        fixture.cleanUp()

    def test_ubuntu_update_apt_sources_fixtures_dont_update(self):

        def setup_function():
            fd = tempfile.NamedTemporaryFile(prefix="sotatest", delete=False, mode="w+")
            for each in mock_apt_sources_list:
                fd.write(each)
            return fd.name

        def teardown_function(fixture):
            (fixture)

        fixture = fixtures.FunctionFixture(setup_function, teardown_function)
        fixture.setUp()
        payload = "dispatcher: testdontupdate \n\t"

        setup_helper = DebianBasedSetupHelper(None)
        setup_helper.update_sources(payload, filename=fixture.fn_result)

        c = ""
        with open(fixture.fn_result) as f:
            for line in f:
                c += line

        self.assertEqual(mock_apt_sources_list, c)
        fixture.cleanUp()

    @patch('dispatcher.sota.setup_helper.YoctoSetupHelper._is_mender_file_exists')
    def test_yocto_pre_processing(self, mock_is_mender_file_exists):
        factory = SotaOsFactory(
            MockDispatcherCallbacks.build_mock_dispatcher_callbacks(), None).get_os('YoctoX86_64')
        setup_helper = factory.create_setup_helper()
        setup_helper.pre_processing()
        mock_is_mender_file_exists.assert_called_once()
