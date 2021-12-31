import json
import unittest
from unittest import TestCase

from dispatcher.command import Command
from mock import patch

from dispatcher.dispatcher_broker import DispatcherBroker


class TestCommand(TestCase):

    def setUp(self):
        patcher = patch('shortuuid.uuid', return_value='12345')
        self.mock_uuid = patcher.start()
        self.addCleanup(patcher.stop)
        self.obj = Command('Test_Command', DispatcherBroker(), '100')

    def test_command_creation_success(self):
        self.assertIsNotNone(self.obj)

    def test_command_name_set(self):
        self.assertEquals(self.obj.command, 'Test_Command')

    def test_id_set(self):
        self.assertEquals(self.obj._id, '12345')

    def test_request_topic_set(self):
        self.assertEquals(self.obj.create_request_topic(),
                          'diagnostic/command/Test_Command')

    def test_response_topic_set(self):
        self.assertEquals(self.obj.create_response_topic(),
                          'diagnostic/response/12345')

    def test_create_payload(self):
        payload = json.loads(self.obj.create_payload())
        self.assertEquals(payload['cmd'], 'Test_Command')
        self.assertEquals(payload['id'], '12345')
        self.assertEquals(payload['size'], '100')


if __name__ == '__main__':
    unittest.main()
