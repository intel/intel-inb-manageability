"""
    Agent which monitors and reports the state of critical components of the framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
from threading import Thread
from typing import List, Tuple

from inbm_lib.dbs_parser import parse_docker_bench_security_results
from inbm_lib.trtl import Trtl
from inbm_common_lib.shell_runner import PseudoShellRunner

logger = logging.getLogger(__name__)


class DockerBenchRunner(Thread):
    """Runs the DBS script on all containers and images.  Parses results"""

    def __init__(self):
        Thread.__init__(self, name="dockerBenchRunner")
        self.result = None
        self.result_string = None
        self.failed_image_list = None
        self.failed_container_list = None

    def run(self):
        """Runs the DockerBenchRunner thread"""
        out = Trtl(PseudoShellRunner()).run_docker_bench_security_test()

        logger.debug(out)
        if out:
            self.result, self.result_string, self.failed_container_list, self.failed_image_list = \
                DockerBenchRunner._handle_docker_security_test_results(out)

    @staticmethod
    def _return_build_result(success_flag,
                             result,
                             fails,
                             failed_images,
                             failed_containers) -> Tuple[bool, str, List[str], List[str]]:
        if success_flag:
            result += "All Passed"
            return True, result.strip(','), [], []
        else:
            result += fails
            logger.debug("Failed Images:" + str(failed_images))
            logger.debug("Failed Containers:" + str(failed_containers))
            return False, result.strip(','), failed_containers, failed_images

    @staticmethod
    def _handle_docker_security_test_results(output: str)\
            -> Tuple[bool, str, List[str], List[str]]:
        parse_result = parse_docker_bench_security_results(output)
        return DockerBenchRunner.\
            _return_build_result(success_flag=parse_result['success_flag'],
                                 result=parse_result['result'],
                                 fails=parse_result['fails'],
                                 failed_images=parse_result['failed_images'],
                                 failed_containers=parse_result['failed_containers'])
