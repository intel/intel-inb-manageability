from unittest import TestCase

from dispatcher.config.config_command import ConfigCommand


class TestConfig(TestCase):

    def test_config(self) -> None:
        command = ConfigCommand("foo1", path="foo2", header_string="foo3")
        self.assertTrue(len(command.create_request_topic()) > 0)
        self.assertTrue(len(command.create_response_topic()) > 0)
        self.assertTrue("foo3" in command.create_payload())
