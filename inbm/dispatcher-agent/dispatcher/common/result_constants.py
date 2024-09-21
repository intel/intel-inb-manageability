"""
    Result Constants used throughout the dispatcher agent

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import json
from ..constants import CACHE


# Result codes (based on HTTP status codes)
CODE_OK = 200
CODE_MULTIPLE = 300
CODE_FOUND = 302
CODE_BAD_REQUEST = 400
CODE_UNAUTHORIZED = 401
CODE_NOT_FOUND = 404


# Result object classes
class Result:

    __slots__ = ("status", "message", "job_id", "json")

    def __init__(self, status: int = 0, message: str = "", job_id: str = "") -> None:
        """Result object containing a status code and message

        @param status: (int) Predefined status code
        @param message: (str) Result message
        @param job_id: (str) Job ID"""
        self.status = status
        self.message = message
        self.job_id = job_id
        self.json = json.dumps({
            "job_id": job_id,
            "status": status,
            "message": str(message)
        })

    def __eq__(self, other: object) -> bool:
        return self.json == str(other)

    def __hash__(self) -> int:
        return self.json.__hash__()

    def __repr__(self) -> str:
        return self.json


# Failure result constants
INSTALL_FAILURE = Result(
    CODE_BAD_REQUEST, "FAILED TO INSTALL")
OTA_FAILURE_IN_PROGRESS = Result(
    CODE_FOUND, "ANOTHER OTA IN PROGRESS, TRY LATER")
OTA_FAILURE = Result(
    CODE_FOUND, "OTA FAILURE")
UNABLE_TO_DOWNLOAD_DOCKER_COMPOSE = Result(
    CODE_BAD_REQUEST, "Unable to download docker-compose container.")
FILE_NOT_FOUND = Result(
    CODE_NOT_FOUND, "FILE NOT FOUND")
IMAGE_IMPORT_FAILURE = Result(
    CODE_UNAUTHORIZED, "FAILED IMAGE IMPORT, IMAGE ALREADY PRESENT")
UNABLE_TO_DOWNLOAD_APPLICATION_PACKAGE = Result(
    CODE_BAD_REQUEST, "Unable to download application package.")


# Successful result constants
COMMAND_SUCCESS = Result(CODE_OK, "COMMAND SUCCESSFUL")
INSTALL_SUCCESS = Result(CODE_OK, "SUCCESSFUL INSTALL")
PUBLISH_SUCCESS = Result(CODE_OK, "MANIFEST PUBLISH SUCCESSFUL")
CONFIG_LOAD_SUCCESS = Result(CODE_OK, "Configuration load: SUCCESSFUL")
CONFIG_LOAD_FAIL_WRONG_PATH = Result(
    CODE_BAD_REQUEST, 'Configuration load: Invalid configuration load path. The conf file is expected to be under ' + CACHE)
