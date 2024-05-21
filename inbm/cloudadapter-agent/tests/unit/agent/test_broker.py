"""
Unit tests for the Broker class


"""


import unittest
import mock

from cloudadapter.agent.broker import Broker, TC_TOPIC

from cloudadapter.constants import AGENT, SCHEDULE, TC_REQUEST_CHANNEL, TC_RESPONSE_CHANNEL, SHUTDOWN, RESTART, INSTALL, COMMAND, CLIENT_CERTS, CLIENT_KEYS


class TestBroker(unittest.TestCase):

    @mock.patch('cloudadapter.agent.broker.MQTT', autospec=True)
    def setUp(self, MockMQTT) -> None:
        self.MockMQTT = MockMQTT
        self.broker = Broker()

    @mock.patch("os.path.islink")
    def test_init_raises_value_error_if_certs_or_keys_are_symlinks(self, mock_islink) -> None:
        # Make os.path.islink return True for either CLIENT_CERTS or CLIENT_KEYS
        mock_islink.side_effect = lambda path: path == CLIENT_CERTS or path == CLIENT_KEYS

        # Check if ValueError is raised when initializing Broker with symbolic links
        with self.assertRaises(ValueError) as context:
            Broker()

        expected_error_message = f"CLIENT_CERTS ({CLIENT_CERTS}) and CLIENT_KEYS ({CLIENT_KEYS}) should not be symbolic links."
        self.assertEqual(str(context.exception), expected_error_message)

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_telemetry_succeeds(self, mock_logger) -> None:
        self.broker.bind_callback(TC_TOPIC.TELEMETRY, lambda: None)

        mocked = self.MockMQTT.return_value
        assert mocked.subscribe.call_count == len(TC_TOPIC.TELEMETRY)
        for args, _ in mocked.subscribe.call_args_list:
            assert args[0] in TC_TOPIC.TELEMETRY
        assert mock_logger.error.call_count == 0

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_state_succeeds(self, mock_logger) -> None:
        self.broker.bind_callback(TC_TOPIC.STATE, lambda: None)

        mocked = self.MockMQTT.return_value
        assert mocked.subscribe.call_count == len(TC_TOPIC.STATE)
        for args, _ in mocked.subscribe.call_args_list:
            assert args[0] in TC_TOPIC.STATE
        assert mock_logger.error.call_count == 0

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_event_succeeds(self, mock_logger) -> None:
        self.broker.bind_callback(TC_TOPIC.EVENT, lambda: None)

        mocked = self.MockMQTT.return_value
        assert mocked.subscribe.call_count == len(TC_TOPIC.EVENT)
        for args, _ in mocked.subscribe.call_args_list:
            assert args[0] in TC_TOPIC.EVENT
        assert mock_logger.error.call_count == 0

    @mock.patch('cloudadapter.agent.broker.logger')
    def test_bind_callback_bad_topic_fails(self, mock_logger) -> None:
        topic = "invalid"

        self.broker.bind_callback(topic, lambda: None)

        mock_logger.error.assert_called_once_with(
            "Attempted to subscribe to unsupported topic: %s",
            topic
        )

    def test_start_mqtt_succeeds(self) -> None:
        self.broker.start()

        mocked = self.MockMQTT.return_value
        mocked.start.assert_called_once_with()

    def test_start_publish_state_succeeds(self) -> None:
        self.broker.start()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(f"{AGENT}/state", "running", retain=True)

    def test_stop_mqtt_succeeds(self) -> None:
        self.broker.stop()

        mocked = self.MockMQTT.return_value
        mocked.stop.assert_called_once_with()

    def test_stop_publish_state_succeeds(self) -> None:
        self.broker.stop()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(f"{AGENT}/state", "dead", retain=True)

    def test_publish_reboot_succeeds(self) -> None:
        self.broker.publish_reboot()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(TC_REQUEST_CHANNEL + RESTART, '', retain=True)

    def test_publish_shutdown_succeeds(self) -> None:
        self.broker.publish_shutdown()

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(TC_REQUEST_CHANNEL + SHUTDOWN, '', retain=True)

    def test_publish_install_succeeds(self) -> None:
        manifest = "<manifest></manifest>"

        self.broker.publish_install(manifest)

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(
            TC_REQUEST_CHANNEL + INSTALL, manifest, retain=False)

    def test_publish_schedule_succeeds(self) -> None:
        schedule = "<schedule_request><request_id>1234</request_id></schedule_request>"

        self.broker.publish_schedule(schedule, "1234", 3)

        mocked = self.MockMQTT.return_value
        mocked.publish_and_wait_response.assert_called_once_with(
            TC_REQUEST_CHANNEL + SCHEDULE, 
            TC_RESPONSE_CHANNEL + "1234",
            schedule, 
            3)

    def test_publish_command_succeeds(self) -> None:
        command = "<command></command>"

        self.broker.publish_command(command)

        mocked = self.MockMQTT.return_value
        mocked.publish.assert_called_once_with(
            TC_REQUEST_CHANNEL + COMMAND, command, retain=False)
