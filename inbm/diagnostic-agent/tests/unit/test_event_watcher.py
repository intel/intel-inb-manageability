from unittest import TestCase

from diagnostic.constants import EVENTS_CHANNEL
from diagnostic.event_watcher import EventWatcher

from threading import Thread

import mock

from diagnostic.ibroker import IBroker


class mock_mqtt(IBroker):

    def __init__(self) -> None:
        self.channel = None
        self.message = None
        self.call_count = 0

    def publish(self, channel, message) -> None:
        self.call_count += 1
        self.channel = channel
        self.message = message

    def stop(self) -> None:
        pass


class mock_dbs():

    def __init__(self, container_list, imge_list, result) -> None:
        self.failed_container_list = container_list
        self.failed_image_list = imge_list
        self.result_string = result


class TestEventWatcher(TestCase):

    def test_parse_dbs_result_fail_no_result(self) -> None:
        result = None
        mqtt = mock_mqtt()
        ev = EventWatcher(mqtt)
        ev._parse_dbs_result(result, None)
        self.assertEquals(mqtt.channel, EVENTS_CHANNEL)
        self.assertEquals(mqtt.message, 'Unable to run Docker Bench Security')
        self.assertEquals(mqtt.call_count, 1)

    def test_parse_dbs_result_fail(self) -> None:
        result = True
        mqtt = mock_mqtt()
        ev = EventWatcher(mqtt)
        dbs = mock_dbs('[123, 456]', '[345]', 'Failed: 1.1, 1.2')
        ev._parse_dbs_result(result, dbs)
        self.assertEquals(mqtt.channel, EVENTS_CHANNEL)
        self.assertEquals(mqtt.message, 'Docker Bench Security results: Failed: 1.1, 1.2')
        self.assertEquals(mqtt.call_count, 3)

    def test_parse_dbs_result_no_fail(self) -> None:
        result = True
        mqtt = mock_mqtt()
        ev = EventWatcher(mqtt)
        dbs = mock_dbs('', '', 'All tests passed')
        ev._parse_dbs_result(result, dbs)
        self.assertEquals(mqtt.channel, EVENTS_CHANNEL)
        self.assertEquals(mqtt.message, 'Docker Bench Security results: All tests passed')
        self.assertEquals(mqtt.call_count, 1)

    @mock.patch("diagnostic.event_watcher.DockerBenchRunner", autospec=True)
    def test_run_docker_bench_security_on_thread_succeeds(self, MockDockerBenchRunner) -> None:
        mock_db_runner = MockDockerBenchRunner.return_value

        def block() -> None:
            while True:
                continue
        mock_db_runner.start = block

        def test() -> None:
            ev = EventWatcher(mock_mqtt())
            ev._parse_dbs_result = mock.Mock()  # type: ignore[method-assign]
            ev.run_docker_bench_security()

        thread = Thread(target=test)
        thread.daemon = True
        thread.start()
        thread.join(timeout=1)

        assert thread.is_alive() == False
