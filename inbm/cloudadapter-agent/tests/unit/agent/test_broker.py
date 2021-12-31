"""
Unit tests for the Broker class


"""


import unittest
import mock

from cloudadapter.agent.broker import Broker, TC_TOPIC

from cloudadapter.constants import AGENT
from cloudadapter.constants import TC_REQUEST_CHANNEL
from cloudadapter.constants import SHUTDOWN, RESTART, INSTALL


class TestBroker(unittest.TestCase):

    @mock.patch('cloudadapter.agent.broker.MQTT', autospec=True)
    def setUp(self, MockMQTT):
        self.MockMQTT = MockMQTT
        self.broker = Broker()

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_telemetry_suceeds(self, mock_logger):
        self.broker.bind_callback(TC_TOPIC.TELEMETRY, lambda: None)

        mocked = self.MockMQTT.return_value
        assert mocked.subscribe.call_count == len(TC_TOPIC.TELEMETRY)
        for args, _ in mocked.subscribe.call_args_list:
            assert args[0] in TC_TOPIC.TELEMETRY
        assert mock_logger.error.call_count == 0

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_state_suceeds(self, mock_logger):
        self.broker.bind_callback(TC_TOPIC.STATE, lambda: None)

        mocked = self.MockMQTT.return_value
        assert mocked.subscribe.call_count == len(TC_TOPIC.STATE)
        for args, _ in mocked.subscribe.call_args_list:
            assert args[0] in TC_TOPIC.STATE
        assert mock_logger.error.call_count == 0

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_event_suceeds(self, mock_logger):
        self.broker.bind_callback(TC_TOPIC.EVENT, lambda: None)

        mocked = self.MockMQTT.return_value
        assert mocked.subscribe.call_count == len(TC_TOPIC.EVENT)
        for args, _ in mocked.subscribe.call_args_list:
            assert args[0] in TC_TOPIC.EVENT
        assert mock_logger.error.call_count == 0

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_bad_topic_fails(self, mock_logger):
        topic = "invalid"

        self.broker.bind_callback(topic, lambda: None)

        mock_logger.error.assert_called_once_with(
            "Attempted to subscribe to unsupported topic: %s",
            topic
        )

    def test_start_mqtt_suceeds(self):
        self.broker.start()

        mocked = self.MockMQTT.return_value
        mocked.start.assert_called_once_with()

    def test_start_publish_state_suceeds(self):
        self.broker.start()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(f"{AGENT}/state", "running", retain=True)

    def test_stop_mqtt_suceeds(self):
        self.broker.stop()

        mocked = self.MockMQTT.return_value
        mocked.stop.assert_called_once_with()

    def test_stop_publish_state_suceeds(self):
        self.broker.stop()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(f"{AGENT}/state", "dead", retain=True)

    def test_publish_reboot_suceeds(self):
        self.broker.publish_reboot()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(TC_REQUEST_CHANNEL + RESTART, '', retain=True)

    def test_publish_shutdown_suceeds(self):
        self.broker.publish_shutdown()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(TC_REQUEST_CHANNEL + SHUTDOWN, '', retain=True)

    def test_publish_install_suceeds(self):
        manifest = "<manifest></manifest>"

        self.broker.publish_install(manifest)

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(
            TC_REQUEST_CHANNEL + INSTALL, manifest, retain=False)
