"""
    Module which runs the Docker Bench Security check on docker images and containers.
    
    Copyright (C) 2017-2022 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import re

from typing import List, Dict, Union
import traceback

logger = logging.getLogger(__name__)


def parse_docker_bench_security_results(dbs_output: str) -> Dict[str, Union[bool, str, List[str]]]:
    """Parse failed images and containers from DBS output.
    @param dbs_output: Output from DBS.
    @return: Dictionary with DBS results. Keys are success_flag (true/false--did DBS pass?); failed_images,
    failed_containers (lists of container/image names that failed); result (text summary of DBS result);
    and fails (text summary of DBS failures)
    """
    for line in traceback.format_stack():
        logger.debug(line.strip())
    logger.debug("############################# dbs_parser #################################")
    result = "Test results: "
    fails = "Failures in: "
    logger.debug("############################# dbs_parser 1 #################################")
    logger.debug(result)
    logger.debug(fails)
    logger.debug("############################# dbs_parser 2 #################################")
    success_flag = True
    prev_warn = False
    failed_images: List = []
    failed_containers: List = []
    for line in dbs_output.splitlines():
        logger.debug("############################# dbs_parser3 #################################")
        if _is_name_in_line(line, prev_warn):
            logger.debug("############################# dbs_parser4 #################################")
            _fetch_names_for_warn_test(line, failed_containers, failed_images)
            logger.debug(line)
            logger.debug(failed_containers)
            logger.debug(failed_images)
        if _is_test_warn(line):
            logger.debug("############################# dbs_parser5 #################################")
            fails = _add_test_in_fails(line, fails)
            logger.debug(fails)
            success_flag = False
            prev_warn = True
            continue
        prev_warn = False
    return {'success_flag': success_flag,
            'failed_images': failed_images,
            'failed_containers': failed_containers,
            'result': result,
            'fails': fails}


def _is_name_in_line(line: str, prev_warn: bool) -> bool:
    return True if "*" in line and prev_warn else False


def _is_test_warn(line: str) -> bool:
    return True if "WARN" in line else False


def _fetch_names_for_warn_test(line: str, failed_containers: List[str], failed_images: List[str]) -> None:
    logger.debug("############################# _fetch_names_for_warn_test #################################")
    logger.debug(line)
    if ": [" in line:
    #if ": [" in line and "No Healthcheck found:" not in line:
        logger.debug("############################# _fetch_names_for_warn_test if #################################")
        logger.debug(failed_images)
        _append_image_name(line, failed_images)
        logger.debug(failed_images)
    elif ": " in line:
    #elif ": " in line and "No SecurityOptions Found:" not in line:
        logger.debug("############################# _fetch_names_for_warn_test elif #################################")
        logger.debug(failed_images)
        _append_container_name(line, failed_containers)
        logger.debug(failed_containers)
    # if "No Healthcheck found:" in line:
    #     matches = re.findall("^.*\\[WARN\\].*: \\[([^[\\]]*)\\]$", line)
    #     if len(matches) == 1:
    #         name = matches[len(matches) - 1]
    #         if name in failed_images:
    #            failed_images.remove(name)
    # if "No SecurityOptions Found:" in line:
    #     matches = re.findall("^.*\\[WARN\\].*: ([^[]*)$", line)
    #     if len(matches) == 1:
    #         name = matches[len(matches) - 1]
    #         if name in failed_containers:
    #             failed_containers.remove(name)





def _add_test_in_fails(line: str, fails: str) -> str:
    logger.debug("############################# _add_test_in_fails #################################")
    logger.debug(fails)
    fails += line.split(" ")[1] + ","
    logger.debug(fails)
    return fails


DBS_CONTAINER_REGEX = "^.*\\[WARN\\].*: ([^[]*)$"


def _append_container_name(line, failed_containers):
    matches = re.findall(DBS_CONTAINER_REGEX, line)
    if len(matches) == 1:
        name = matches[len(matches) - 1]
        if name not in failed_containers:
            failed_containers.append(name)


DBS_IMAGE_REGEX = "^.*\\[WARN\\].*: \\[([^[\\]]*)\\]$"


def _append_image_name(line, failed_images):
    matches = re.findall(DBS_IMAGE_REGEX, line)
    if len(matches) == 1:
        name = matches[len(matches) - 1]
        if name not in failed_images:
            failed_images.append(name)