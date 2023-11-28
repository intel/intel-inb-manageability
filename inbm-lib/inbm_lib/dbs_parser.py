"""
    Module which runs the Docker Bench Security check on docker images and containers.
    
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import re

from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)

FAILURE = "Failures in: "
TEST_RESULTS = "Test results: "


@dataclass(init=True)
class DBSResult:
    is_success: bool = field(default=True)
    failed_images: List[str] = field(default_factory=lambda: [])
    failed_containers: List[str] = field(default_factory=lambda: [])
    result: str = field(default="Test results: ")
    fails: str = field(default="Failures in: ")


def parse_docker_bench_security_results(dbs_output: str) -> DBSResult:
    """Parse failed images and containers from DBS output.

    @param dbs_output: Output from DBS.

    @return: DBSResult data class.  Fields are success_flag (true/false--did DBS pass?); failed_images,
    failed_containers (lists of container/image names that failed); result (text summary of DBS result);
    and fails (text summary of DBS failures)
    """

    prev_warn = False
    fails = FAILURE
    result = TEST_RESULTS
    is_success = True
    failed_containers:  List[str] = []
    failed_images: List[str] = []
    for line in dbs_output.splitlines():
        if _is_name_in_line(line, prev_warn):
            _fetch_names_for_warn_test(line, failed_containers, failed_images)
        if _is_test_warn(line):
            fails = _add_test_in_fails(line, fails)
            is_success = False
            prev_warn = True
            continue
        prev_warn = False

    return DBSResult(is_success=is_success, fails=fails, result=result,
                     failed_containers=failed_containers, failed_images=failed_images)


def _is_name_in_line(line: str, prev_warn: bool) -> bool:
    return True if "*" in line and prev_warn else False


def _is_test_warn(line: str) -> bool:
    return True if "WARN" in line else False


def _fetch_names_for_warn_test(line: str, failed_containers: List[str], failed_images: List[str]) -> None:
    if ": [" in line:
        _append_image_name(line, failed_images)
    elif ": " in line:
        _append_container_name(line, failed_containers)


def _add_test_in_fails(line: str, fails: str) -> str:
    fails += line.split(" ")[1] + ","
    return fails


DBS_CONTAINER_REGEX = "^.*\\[WARN\\].*: ([^[]*)$"


def _append_container_name(line: str, failed_containers: list[str]) -> None:
    matches = re.findall(DBS_CONTAINER_REGEX, line)
    if len(matches) == 1:
        name = matches[len(matches) - 1]
        if name not in failed_containers:
            failed_containers.append(name)


DBS_IMAGE_REGEX = "^.*\\[WARN\\].*: \\[([^[\\]]*)\\]$"


def _append_image_name(line: str, failed_images: list[str]) -> None:
    matches = re.findall(DBS_IMAGE_REGEX, line)
    if len(matches) == 1:
        name = matches[len(matches) - 1]
        if name not in failed_images:
            failed_images.append(name)
