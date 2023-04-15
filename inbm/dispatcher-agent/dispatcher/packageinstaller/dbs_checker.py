"""
    Module which runs the Docker Bench Security check on docker images and containers.
    
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging

from typing import Any, List, Optional, Tuple, Union

from inbm_lib.dbs_parser import parse_docker_bench_security_results
from .constants import EVENTS_CHANNEL, REMEDIATION_CONTAINER_CMD_CHANNEL, \
    REMEDIATION_IMAGE_CMD_CHANNEL
from inbm_lib.trtl import Trtl
from ..common.result_constants import Result
from ..config_dbs import ConfigDbs
from ..dispatcher_callbacks import DispatcherCallbacks
from ..dispatcher_exception import DispatcherException

logger = logging.getLogger(__name__)


class DbsChecker:
    """Checks the DBS report for containers/images that need remediation

    @param dispatcher_callbacks: DispatcherCallbacks instance
    @param container_callback:  Callback to TrtlContainer object
    @param trtl: TRTL object
    @param name: container name
    @param last_version: container version
    """

    def __init__(self,
                 dispatcher_callbacks: DispatcherCallbacks,
                 container_callback: Any,
                 trtl: Trtl,
                 name: str,
                 last_version: int,
                 config_dbs: ConfigDbs
                 ) -> None:
        self._dispatcher_callbacks = dispatcher_callbacks
        self._container_callback = container_callback
        self._trtl = trtl
        self._name = name
        self._last_version = last_version
        self._config_dbs = config_dbs

    def check(self) -> Result:
        """Checks DBS status when an AOTA is initiated.

        @return: status
        """
        try:
            self.run_docker_security_test()
            if self._trtl.stop(self._name, self._last_version - 1):
                container_id = self._find_current_container()
                self._trtl.commit(self._name, self._last_version)
                logger.debug("rpm_install: based on smart install, detected success")
                return self._container_callback.check_config_params_start_container(self._name,
                                                                                    self._last_version,
                                                                                    container_id)
            else:
                return self._container_callback.rollback()
        except DispatcherException as e:
            logger.error(f'DBS check failed: {str(e)}')
            return self._container_callback.rollback()

    def run_docker_security_test(self) -> str:  # pragma: no cover
        """Calls TRTL API to run DBS

        @return: Result of DBS.  False if unable to run DBS."""
        output = self._trtl.run_docker_bench_security_test()
        logger.debug(output)
        if not output:
            raise DispatcherException("Cannot run docker bench security.")
        return self._handle_docker_security_test_results(output)

    def _handle_docker_security_test_results(self, output: str) -> str:
        parse_result = parse_docker_bench_security_results(output)
        if not isinstance(parse_result['result'], str):
            raise DispatcherException("Internal error: DBS parser returned invalid result type")
        return self._return_build_result(success_flag=parse_result['success_flag'],
                                         result=parse_result['result'],
                                         fails=parse_result['fails'],
                                         failed_images=parse_result['failed_images'],
                                         failed_containers=parse_result['failed_containers'])

    def _return_build_result(self,
                             success_flag: Union[bool, str, List[str]],
                             result: Any,
                             fails: Union[bool, str, List[str]],
                             failed_images: Union[bool, str, List[str]],
                             failed_containers: Union[bool, str, List[str]]) -> str:
        if success_flag:
            result += "All Passed"
            return result.strip(',')
        else:
            result += fails
            logger.debug("Failed Images:" + str(failed_images))
            logger.debug("Failed Containers:" + str(failed_containers))
            self._publish_remediation_request(failed_containers, failed_images)
            self._dispatcher_callbacks.broker_core.mqtt_publish(
                EVENTS_CHANNEL, "Docker Bench Security results: " + result.strip(','))

            if self._config_dbs == ConfigDbs.WARN:
                logger.debug("DBS in WARN mode")
                return result.strip(',')
            raise DispatcherException(result.strip(','))

    def _publish_remediation_request(self, failed_containers: Any, failed_images: Any) -> None:
        if failed_containers and len(failed_containers) > 0:
            self._dispatcher_callbacks.broker_core.mqtt_publish(
                REMEDIATION_CONTAINER_CMD_CHANNEL, str(failed_containers))
        if failed_images and len(failed_images) > 0:
            self._dispatcher_callbacks.broker_core.mqtt_publish(
                REMEDIATION_IMAGE_CMD_CHANNEL, str(failed_images))

    def _find_current_container(self) -> Optional[str]:
        err, out = self._trtl.list()
        if err:
            logger.error("Error encountered while getting container ID")
            return None
        for line in out.splitlines():
            if self._name + ":" + str(self._last_version) in line:
                container_id = line.split()[0]
                return container_id
        return None
