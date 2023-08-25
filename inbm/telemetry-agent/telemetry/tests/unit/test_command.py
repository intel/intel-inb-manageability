from telemetry.command import Command
from unittest import TestCase




class TestCommand(TestCase):

    def test_create_command(self):
        self.assertIsNotNone(Command('container_health_check', 'cloud'))
