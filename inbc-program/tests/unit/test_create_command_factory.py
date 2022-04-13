from unittest import TestCase
from mock import Mock, patch
from inbc.inbc_exception import InbcException
from inbc.command.command_factory import create_command_factory
from inbc.command.command import RestartCommand, QueryCommand
from inbc.command.ota_command import FotaCommand, SotaCommand, PotaCommand
from inbc.command.config_command import LoadConfigCommand, SetConfigCommand, GetConfigCommand, AppendConfigCommand


class TestOsFactory(TestCase):
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_restart_command(self, mock_agent):
        assert type(create_command_factory("restart", Mock())) is RestartCommand

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_query_command(self, mock_agent):
        assert type(create_command_factory("query", Mock())) is QueryCommand

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_fota_command(self, mock_agent):
        assert type(create_command_factory("fota", Mock())) is FotaCommand

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_sota_command(self, mock_agent):
        assert type(create_command_factory("sota", Mock())) is SotaCommand

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_pota_command(self, mock_agent):
        assert type(create_command_factory("pota", Mock())) is PotaCommand

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_load_command(self, mock_agent):
        assert type(create_command_factory("load", Mock())) is LoadConfigCommand
    
    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_get_command(self, mock_agent):
        assert type(create_command_factory("get", Mock())) is GetConfigCommand

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_set_command(self, mock_agent):
        assert type(create_command_factory("set", Mock())) is SetConfigCommand

    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_create_set_command(self, mock_agent):
        assert type(create_command_factory("append", Mock())) is AppendConfigCommand


    @patch('inbc.command.command.is_vision_agent_installed', return_value=True)
    def test_raise_on_invalid_command(self, mock_agent):
        with self.assertRaises(InbcException):
            create_command_factory("app", Mock())
