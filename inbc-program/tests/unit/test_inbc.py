from unittest import TestCase
from inbc.parser.parser import ArgsParser
from inbc.constants import COMMAND_FAIL, COMMAND_SUCCESS
from inbc.inbc_exception import InbcCode, InbcException
from inbc.command.ota_command import FotaCommand, AotaCommand

from inbm_lib.request_message_constants import *
from unittest.mock import patch, Mock


class TestInbc(TestCase):

    def setUp(self) -> None:
        self.arg_parser = ArgsParser()
        self.maxDiff = None

    @patch('threading.Thread._bootstrap_inner')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_lib.timer.Timer.stop')
    def test_aota_terminate_operation_success(self, t_stop, mock_reconnect, mock_thread) -> None:
        c = AotaCommand(Mock())
        c.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        print(t_stop.call_count)
        assert t_stop.call_count == 1

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_lib.timer.Timer.stop')
    def test_aota_terminate_operation_failed(self, t_stop, mock_reconnect) -> None:
        c = AotaCommand(Mock())
        c.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        t_stop.assert_called_once()

    @patch('threading.Thread._bootstrap_inner')
    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_lib.timer.Timer.stop')
    def test_fota_terminate_operation_success(self, t_stop, mock_reconnect, mock_thread) -> None:
        c = FotaCommand(Mock())
        c.terminate_operation(COMMAND_SUCCESS, InbcCode.SUCCESS.value)
        print(t_stop.call_count)
        assert t_stop.call_count == 1

    @patch('inbm_lib.mqttclient.mqtt.mqtt.Client.reconnect')
    @patch('inbm_lib.timer.Timer.stop')
    def test_fota_terminate_operation_failed(self, t_stop, mock_reconnect) -> None:
        c = FotaCommand(Mock())
        c.terminate_operation(COMMAND_FAIL, InbcCode.FAIL.value)
        t_stop.assert_called_once()
