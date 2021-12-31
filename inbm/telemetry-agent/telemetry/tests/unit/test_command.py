from telemetry.command import Command
from unittest import TestCase
from future import standard_library
standard_library.install_aliases()


class TestCommand(TestCase):

    def test_create_command(self):
        self.assertIsNotNone(Command('container_health_check', 'cloud'))
