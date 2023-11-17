from unittest import TestCase

from diagnostic.constants import EVENTS_CHANNEL
from diagnostic.event_watcher import EventWatcher
from inbm_lib.dbs_parser import DBSResult

from threading import Thread

import mock


class mock_mqtt():

    def __init__(self):
        self.channel = None
        self.message = None
        self.call_count = 0

    def publish(self, channel, message):
        self.call_count += 1
        self.channel = channel
        self.message = message


class mock_dbs():

    def __init__(self, container_list, image_list, result):
        self.dbs_result = DBSResult()
        self.dbs_result.failed_containers = container_list
        self.dbs_result.failed_images = image_list
        self.dbs_result.result = result


class TestEventWatcher(TestCase):

    def test_parse_dbs_result_fail_no_result(self):
        mqtt = mock_mqtt()
        ev = EventWatcher(mqtt)
        ev._parse_dbs_result(None, None)
        self.assertEqual(mqtt.channel, EVENTS_CHANNEL)
        self.assertEqual(mqtt.message, 'Unable to run Docker Bench Security')
        self.assertEqual(mqtt.call_count, 1)

    def test_parse_dbs_result_fail(self):
        mqtt = mock_mqtt()
        ev = EventWatcher(mqtt)
        dbs = mock_dbs('[123, 456]', '[345]', 'Failed: 1.1, 1.2')
        ev._parse_dbs_result(True, dbs)
        self.assertEqual(mqtt.channel, EVENTS_CHANNEL)
        self.assertEqual(mqtt.message, 'Docker Bench Security results: Failed: 1.1, 1.2')
        self.assertEqual(mqtt.call_count, 3)

    def test_parse_dbs_result_no_fail(self):
        mqtt = mock_mqtt()
        ev = EventWatcher(mqtt)
        dbs = mock_dbs('', '', 'All tests passed')
        ev._parse_dbs_result(True, dbs)
        self.assertEqual(mqtt.channel, EVENTS_CHANNEL)
        self.assertEqual(mqtt.message, 'Docker Bench Security results: All tests passed')
        self.assertEqual(mqtt.call_count, 1)

    @mock.patch("diagnostic.event_watcher.DockerBenchRunner", autospec=True)
    def test_run_docker_bench_security_on_thread_succeeds(self, MockDockerBenchRunner):
        mock_db_runner = MockDockerBenchRunner.return_value

        def block():
            while True:
                continue

        mock_db_runner.start = block

        def test():
            ev = EventWatcher(mock_mqtt())
            ev._parse_dbs_result = mock.Mock()
            ev.run_docker_bench_security()

        thread = Thread(target=test)
        thread.daemon = True
        thread.start()
        thread.join(timeout=1)

        assert thread.is_alive() == False
