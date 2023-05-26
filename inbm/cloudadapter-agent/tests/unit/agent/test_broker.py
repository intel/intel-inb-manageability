"""
Unit tests for the Broker class


"""


import unittest
import mock

from cloudadapter.agent.broker import Broker, TC_TOPIC

from cloudadapter.constants import AGENT, TC_REQUEST_CHANNEL, SHUTDOWN, RESTART, INSTALL, COMMAND, CLIENT_CERTS, CLIENT_KEYS


class TestBroker(unittest.TestCase):

    @mock.patch('cloudadapter.agent.broker.MQTT', autospec=True)
    def setUp(self, MockMQTT):
        self.MockMQTT = MockMQTT
        self.broker = Broker()

    @mock.patch("os.path.islink")
    def test_init_raises_value_error_if_certs_or_keys_are_symlinks(self, mock_islink):
        # Make os.path.islink return True for either CLIENT_CERTS or CLIENT_KEYS
        mock_islink.side_effect = lambda path: path == CLIENT_CERTS or path == CLIENT_KEYS

        # Check if ValueError is raised when initializing Broker with symbolic links
        with self.assertRaises(ValueError) as context:
            Broker()

        expected_error_message = f"CLIENT_CERTS ({CLIENT_CERTS}) and CLIENT_KEYS ({CLIENT_KEYS}) should not be symbolic links."
        self.assertEqual(str(context.exception), expected_error_message)    

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_telemetry_succeeds(self, mock_logger):
        self.broker.bind_callback(TC_TOPIC.TELEMETRY, lambda: None)

        mocked = self.MockMQTT.return_value
        assert mocked.subscribe.call_count == len(TC_TOPIC.TELEMETRY)
        for args, _ in mocked.subscribe.call_args_list:
            assert args[0] in TC_TOPIC.TELEMETRY
        assert mock_logger.error.call_count == 0

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_state_succeeds(self, mock_logger):
        self.broker.bind_callback(TC_TOPIC.STATE, lambda: None)

        mocked = self.MockMQTT.return_value
        assert mocked.subscribe.call_count == len(TC_TOPIC.STATE)
        for args, _ in mocked.subscribe.call_args_list:
            assert args[0] in TC_TOPIC.STATE
        assert mock_logger.error.call_count == 0

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_event_succeeds(self, mock_logger):
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

    def test_start_mqtt_succeeds(self):
        self.broker.start()

        mocked = self.MockMQTT.return_value
        mocked.start.assert_called_once_with()

    def test_start_publish_state_succeeds(self):
        self.broker.start()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(f"{AGENT}/state", "running", retain=True)

    def test_stop_mqtt_succeeds(self):
        self.broker.stop()

        mocked = self.MockMQTT.return_value
        mocked.stop.assert_called_once_with()

    def test_stop_publish_state_succeeds(self):
        self.broker.stop()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(f"{AGENT}/state", "dead", retain=True)

    def test_publish_reboot_succeeds(self):
        self.broker.publish_reboot()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(TC_REQUEST_CHANNEL + RESTART, '', retain=True)

    def test_publish_shutdown_succeeds(self):
        self.broker.publish_shutdown()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(TC_REQUEST_CHANNEL + SHUTDOWN, '', retain=True)

    def test_publish_install_succeeds(self):
        manifest = "<manifest></manifest>"

        self.broker.publish_install(manifest)

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(
            TC_REQUEST_CHANNEL + INSTALL, manifest, retain=False)

    def test_publish_command_succeeds(self):
        command = "<command></command>"

        self.broker.publish_command(command)

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(
            TC_REQUEST_CHANNEL + COMMAND, command, retain=False)
