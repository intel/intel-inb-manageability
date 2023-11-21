from unittest import TestCase

from unit.common.mock_resources import *
from dispatcher.fota.rebooter import *
from mock import patch


class TestRebooter(TestCase):

    def setUp(self):
        self.mock_disp_callbacks_obj = MockDispatcherCallbacks.build_mock_dispatcher_callbacks()
        self.mock_disp_broker_obj = MockDispatcherBroker.build_mock_dispatcher_broker()

    @patch('time.sleep', return_value=None)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', side_effect=[('', '', None), ('', '', 0), ('', '', -1)])
    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    def test_reboot_linux(self, mock_runner, mock_call_telemetry, mock_sleep):
        LinuxRebooter(self.mock_disp_callbacks_obj, self.mock_disp_broker_obj).reboot()
        if mock_runner.side_effect in [('', '', None), ('', '', 0)]:
            mock_call_telemetry.assert_not_called()
        else:
            mock_call_telemetry.assert_called()
