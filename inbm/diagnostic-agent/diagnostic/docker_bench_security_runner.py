"""
    Agent which monitors and reports the state of critical components of the framework

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from threading import Thread
from dataclasses import replace

from inbm_lib.dbs_parser import parse_docker_bench_security_results, DBSResult, FAILURE
from inbm_lib.trtl import Trtl
from inbm_common_lib.shell_runner import PseudoShellRunner

logger = logging.getLogger(__name__)


class DockerBenchRunner(Thread):
    """Runs the DBS script on all containers and images.  Parses results"""

    def __init__(self) -> None:
        Thread.__init__(self, name="dockerBenchRunner")
        self.dbs_result = DBSResult()

    def run(self) -> None:
        """Runs the DockerBenchRunner thread"""
        out = Trtl(PseudoShellRunner()).run_docker_bench_security_test()

        logger.debug(out)
        if out:
            self.dbs_result = DockerBenchRunner._handle_docker_security_test_results(out)
        else:
            self.dbs_result = DBSResult(is_success=False, result="", failed_containers=[],
                                        failed_images=[], fails=FAILURE)

    @staticmethod
    def _handle_docker_security_test_results(output: str) -> DBSResult:
        dbs_result = parse_docker_bench_security_results(output)
        logger.info(f"is_success={dbs_result.is_success}")
        if dbs_result.is_success:
            return replace(dbs_result, result=(dbs_result.result + "All Passed").strip(','),
                           failed_containers=[], failed_images=[])
        else:
            _dbs_result = replace(dbs_result, result=(
                dbs_result.result + dbs_result.fails).strip(','))
            logger.debug("Failed Images:" + str(dbs_result.failed_images))
            logger.debug("Failed Containers:" + str(dbs_result.failed_containers))
            return _dbs_result
