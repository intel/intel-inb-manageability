from unittest import TestCase
from mock import patch
from ast import literal_eval
from dispatcher.remediationmanager.remediation_manager import RemediationManager
from unit.common.mock_resources import *


class TestRemediationManager(TestCase):

    def setUp(self):
        self.mock_disp_callbacks_obj = MockDispatcherCallbacks.build_mock_dispatcher_callbacks()

    @patch('dispatcher.remediationmanager.remediation_manager.RemediationManager._remove_container')
    def test_on_stop_container_success(self, mock_remove_container):
        try:
            RemediationManager(self.mock_disp_callbacks_obj)._on_stop_container(
                'remediation/container', '[123, 234, 567]', 1)
            mock_remove_container.assert_called()
        except ValueError:
            self.fail("_on_stop_container() raised ValueError unexpectedly!")

    @patch('dispatcher.remediationmanager.remediation_manager.RemediationManager._remove_images')
    def test_on_remove_image_success(self, mock_remove_images):
        try:
            RemediationManager(self.mock_disp_callbacks_obj)._on_remove_image(
                'remediation/image', str(['abc123', 'def234']), 1)
            mock_remove_images.assert_called()
        except ValueError:
            self.fail("_on_remove_images() raised ValueError unexpectedly!")

    def test_run(self):
        try:
            RemediationManager(self.mock_disp_callbacks_obj).run()
        except Exception:
            self.fail("run() raised Exception unexpectedly!")

    @patch('inbm_lib.trtl.Trtl.list', return_value=(None, ['abc123', 'def234', 'ghi567']))
    @patch('inbm_lib.trtl.Trtl.image_remove_by_id', return_value=(None, None, 0))
    @patch('inbm_lib.trtl.Trtl.get_image_by_container_id', return_value=('ImageID= sha256:fbf60236a8e3dd08a08966064a8ac9f3943ecbffa6ae2ad9bc455974b956412c ,ImageName= ubuntu:bionic', None, 0))
    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    @patch('inbm_lib.trtl.Trtl.stop_by_id')
    @patch('inbm_lib.trtl.Trtl.remove_container')
    def test_return_container_no_errors(self, mock_remove_container, mock_stop_by_id, mock_call_telemetry, mock_image, mock_remove, mock_list):
        try:
            mock_stop_by_id.return_value = (None, None, 0)
            mock_remove_container.return_value = None

            rm = RemediationManager(self.mock_disp_callbacks_obj)
            rm.ignore_dbs_results = False
            rm._remove_container(literal_eval(str(['abc123', 'def234', 'ghi567'])))
        except ValueError:
            self.fail("RemediationManager raised ValueError exception unexpectedly!")
        mock_call_telemetry.assert_called()
        mock_remove_container.assert_called()
        mock_stop_by_id.assert_called()

    @patch('inbm_lib.trtl.Trtl.list', return_value=(None, [123, 234, 567]))
    @patch('inbm_lib.trtl.Trtl.image_remove_by_id', return_value=(None, None, 0))
    @patch('inbm_lib.trtl.Trtl.get_image_by_container_id', return_value=(None, 'cannot find', 3))
    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    @patch('inbm_lib.trtl.Trtl.stop_by_id')
    @patch('inbm_lib.trtl.Trtl.remove_container')
    def test_return_container_raises_error_on_bad_format(self, mock_remove_container, mock_stop_by_id,
                                                         mock_call_telemetry, mock_image, mock_remove, mock_list):
        mock_stop_by_id.return_value = (None, None, 0)
        mock_remove_container.return_value = None
        mock_call_telemetry.assert_not_called()
        with self.assertRaises(ValueError):
            rm = RemediationManager(self.mock_disp_callbacks_obj)
            rm.ignore_dbs_results = False
            rm._remove_container('[123, 234, 567]')
    @patch('inbm_lib.trtl.Trtl.image_remove_by_id', return_value=(None, None, 0))
    @patch('inbm_lib.trtl.Trtl.get_image_by_container_id', return_value=('abc', None, 0))
    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    @patch('inbm_lib.trtl.Trtl.stop_by_id')
    @patch('inbm_lib.trtl.Trtl.remove_container')
    def test_telemetry_call_when_stop_errors(self, mock_remove_container, mock_stop_by_id, mock_call_telemetry,
                                             mock_image, mock_remove):
        mock_stop_by_id.return_value = (None, 'error', 1)
        mock_remove_container.return_value = None
        RemediationManager(self.mock_disp_callbacks_obj)._remove_container(
            str(['abc123', 'def234', 'ghi567']))
        mock_call_telemetry.assert_called()

    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    @patch('inbm_lib.trtl.Trtl.image_remove_by_id')
    def test_return_image_no_errors(self, mock_remove_image, mock_call_telemetry):
        try:
            mock_remove_image.return_value = (None, None, 0)
            rm = RemediationManager(self.mock_disp_callbacks_obj)
            rm.ignore_dbs_results = False
            rm._remove_images(str(['abc123', 'def234', 'ghi567']))
        except ValueError:
            self.fail("RemediationManager raised ValueError exception unexpectedly!")
        mock_call_telemetry.assert_called()
        mock_remove_image.assert_called()

    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    @patch('inbm_lib.trtl.Trtl.image_remove_by_id')
    def test_telemetry_call_when_remove_image_errors(self, mock_remove_image, mock_call_telemetry):
        mock_remove_image.return_value = (None, 'error', 1)
        RemediationManager(self.mock_disp_callbacks_obj)._remove_images(
            str(['abc123', 'def234', 'ghi567']))
        mock_call_telemetry.assert_called()
    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    @patch('inbm_lib.trtl.Trtl.image_remove_by_id')
    def test_ignore_dbs_results_does_not_remove_image(self,  mock_remove_image, mock_call_telemetry):
        r = RemediationManager(self.mock_disp_callbacks_obj)
        r.ignore_dbs_results = True
        r._remove_images(str(['abc123', 'def234', 'ghi567']))
        mock_call_telemetry.assert_called()
        mock_remove_image.assert_not_called()

    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    @patch('inbm_lib.trtl.Trtl.stop_by_id')
    @patch('inbm_lib.trtl.Trtl.remove_container')
    def test_telemetry_call_when_remove_container_errors(self, mock_remove_container, mock_stop_by_id,
                                                         mock_call_telemetry):

        r = RemediationManager(self.mock_disp_callbacks_obj)
        r.ignore_dbs_results = True
        r._remove_images(str(['abc123', 'def234', 'ghi567']))
        mock_call_telemetry.assert_called()
        mock_remove_container.assert_not_called()
        mock_stop_by_id.assert_not_called()

    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    @patch('inbm_lib.trtl.Trtl.image_remove_by_id', return_value=(None, None, 0))
    def test_dbs_not_deleted_twice_with_remove_image_on_failed_container(self,  mock_remove_image, mock_call_telemetry):
        r = RemediationManager(self.mock_disp_callbacks_obj)
        r.ignore_dbs_results = False
        r.container_image_list = ['abc123', 'def234']
        r._remove_images(['abc123', 'def234', 'ghi567'])
        mock_call_telemetry.assert_called()
        mock_remove_image.assert_called_once_with('ghi567', True)

