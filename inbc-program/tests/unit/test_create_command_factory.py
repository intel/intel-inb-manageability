from unittest import TestCase
from mock import Mock
from inbc.inbc_exception import InbcException
from inbc.command.command_factory import create_command_factory
from inbc.command.command import RestartCommand, QueryCommand
from inbc.command.ota_command import FotaCommand, SotaCommand, PotaCommand, AotaCommand
from inbc.command.config_command import LoadConfigCommand, SetConfigCommand, GetConfigCommand, \
    AppendConfigCommand, RemoveConfigCommand


class TestOsFactory(TestCase):

    def test_create_restart_command(self):
        assert type(create_command_factory("restart", Mock())) is RestartCommand

    def test_create_query_command(self):
        assert type(create_command_factory("query", Mock())) is QueryCommand

    def test_create_fota_command(self):
        assert type(create_command_factory("fota", Mock())) is FotaCommand

    def test_create_aota_command(self):
        assert type(create_command_factory("aota", Mock())) is AotaCommand

    def test_create_sota_command(self):
        assert type(create_command_factory("sota", Mock())) is SotaCommand

    def test_create_pota_command(self):
        assert type(create_command_factory("pota", Mock())) is PotaCommand

    def test_create_load_command(self):
        assert type(create_command_factory("load", Mock())) is LoadConfigCommand
    
    def test_create_get_command(self):
        assert type(create_command_factory("get", Mock())) is GetConfigCommand

    def test_create_set_command(self):
        assert type(create_command_factory("set", Mock())) is SetConfigCommand

    def test_create_remove_command(self):
        assert type(create_command_factory("remove", Mock())) is RemoveConfigCommand

    def test_create_append_command(self):
        assert type(create_command_factory("append", Mock())) is AppendConfigCommand

    def test_raise_on_invalid_command(self):
        with self.assertRaises(InbcException):
            create_command_factory("app", Mock())
