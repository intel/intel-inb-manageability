from telemetry.command import Command
from unittest import TestCase


class TestCommand(TestCase):

    def test_create_command(self) -> None:
        self.assertIsNotNone(Command('container_health_check', 'cloud'))
