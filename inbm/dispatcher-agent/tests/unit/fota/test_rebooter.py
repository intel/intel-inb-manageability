from unittest import TestCase

from unit.common.mock_resources import *
from dispatcher.fota.rebooter import *
from unittest.mock import patch


class TestRebooter(TestCase):

    def setUp(self) -> None:
        self.mock_disp_broker_obj = MockDispatcherBroker.build_mock_dispatcher_broker()

    @patch('time.sleep', return_value=None)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', side_effect=[('', '', None), ('', '', 0), ('', '', -1)])
    @patch('unit.common.mock_resources.MockDispatcherBroker.telemetry')
    def test_reboot_linux(self, mock_runner, mock_call_telemetry, mock_sleep) -> None:
        LinuxRebooter(self.mock_disp_broker_obj).reboot()
        if mock_runner.side_effect in [('', '', None), ('', '', 0)]:
            mock_call_telemetry.assert_not_called()
        else:
            mock_call_telemetry.assert_called()
