"""
    Agent which monitors and reports the state of critical components of the framework
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging

from threading import Thread, Lock

from .constants import EVENTS_CHANNEL
from .constants import REMEDIATION_CONTAINER_CHANNEL
from .constants import REMEDIATION_IMAGE_CHANNEL
from .constants import TRTL_EVENTS
from .constants import DEFAULT_DBS_MODE
from .config_dbs import ConfigDbs

from .docker_bench_security_runner import DockerBenchRunner
from inbm_common_lib.shell_runner import PseudoShellRunner

logger = logging.getLogger(__name__)

current_dbs_mode = DEFAULT_DBS_MODE

class EventWatcher(Thread):
    """Starts up a thread to watch for events coming from Docker"""

    def __init__(self, broker):
        self.lock = Lock()
        Thread.__init__(self, name="dockerEventWatcher")
        self._broker = broker
        self.daemon = True
        self._process = None
        self._running = True

    def run(self):  # pragma: no cover
        """Runs the EventWatcher thread"""
        self._process = PseudoShellRunner().get_process(TRTL_EVENTS)
        logger.debug(f'Watching for Docker events on PID: {self._process.pid}')
        self._parse_process_output(self._process)
        logger.debug("Event Watcher thread exited")

    def set_dbs_mode(self, mode_value):
        global current_dbs_mode
        current_dbs_mode = mode_value
        logger.debug(f"Current DBS mode is set to - {current_dbs_mode}")

    def run_docker_bench_security(self):  # pragma: no cover
        """Launch Docker Bench Security in separate thread."""
        def run():
            self.lock.acquire()
            if current_dbs_mode != ConfigDbs.OFF:
                dbs = DockerBenchRunner()
                logger.debug(f"DBS mode : {current_dbs_mode} , Launching DBS checks...")
                dbs.start()
                dbs.join()
                if current_dbs_mode == ConfigDbs.ON:
                    logger.debug("Parsing DBS result after DBS check. . .")
                    self._parse_dbs_result(dbs.result, dbs)
                else:
                    logger.debug(
                        "Failed Images and Containers are not terminated since \
                        DBS is set to - {}".format(current_dbs_mode))
            else:
                logger.debug(
                    "DBS check will not run, since DBS is turned OFF. Mode : {}"
                    .format(current_dbs_mode))
            self.lock.release()
        thread = Thread(target=run)
        thread.daemon = True
        thread.start()

    def _check_failed_containers(self, failed_containers: str) -> None:
        logger.debug("Passing failed containers on REMEDIATION_CONTAINER_CHANNEL")
        if failed_containers and len(failed_containers) > 0:
            self._broker.publish(REMEDIATION_CONTAINER_CHANNEL, str(failed_containers))

    def _check_failed_images(self, failed_images: str) -> None:
        logger.debug("Passing failed images on REMEDIATION_IMAGE_CHANNEL")
        if failed_images and len(failed_images) > 0:
            self._broker.publish(REMEDIATION_IMAGE_CHANNEL,
                                 str(failed_images))

    def _parse_dbs_result(self, result, dbs):
        if result is not None:
            failed_containers = dbs.failed_container_list
            failed_images = dbs.failed_image_list
            result_string = dbs.result_string
            self._check_failed_containers(failed_containers)
            self._check_failed_images(failed_images)
            self._broker.publish(
                EVENTS_CHANNEL, "Docker Bench Security results: " + result_string)
        else:
            self._broker.publish(EVENTS_CHANNEL, "Unable to run Docker Bench Security")

    @staticmethod
    def _output_ended(next_line, process):
        return True if next_line == '' and process.poll() is not None else False

    def _process_output(self, events, next_line):
        if len(events) < 3:
            logger.debug(
                " ".join(TRTL_EVENTS) +
                " command unexpected line (not enough fields): [" +
                next_line + "]")
        else:
            event_type = events[2]
            obj_id = events[1]
            action = events[0]
            logger.info(action + " on " + event_type + " with id " + obj_id)
            if action.strip() == 'start' and event_type.strip() == 'container' \
                    and 'docker-bench-security' not in events[3]:
                logger.debug('DBS check triggered via action: ' +
                             action.strip() + ' event: ' + event_type.strip())
                self.run_docker_bench_security()

            logger.debug(" ".join(TRTL_EVENTS) + " command done processing.")

    def _parse_process_output(self, process):
        while self._running:
            logger.debug(" ".join(TRTL_EVENTS) + " command output log start.")
            # we filter out bad characters but still accept the rest of the string
            # here based on experience running the underlying command
            next_line = process.stdout.readline().decode('utf-8', errors='replace')
            if self._output_ended(next_line, process):
                break
            logger.debug(" ".join(TRTL_EVENTS) + " command output log: [" + next_line + "]")
            events = next_line.split('\t')
            self._process_output(events, next_line)

    def stop(self):
        """Stop event watcher"""
        self._running = False
