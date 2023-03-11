"""
    Result Constants used throughout the dispatcher agent

    Copyright (C) 2017-2023 Intel Corporation
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

    __slots__ = ("status", "message", "json")

    def __init__(self, status: int = 0, message: str = "") -> None:
        """Result object containing a status code and message

        @param status: (int) Predefined status code
        @param message: (str) Result message"""
        self.status = status
        self.message = message
        self.json = json.dumps({
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
UNABLE_TO_START_DOCKER_COMPOSE = Result(
    CODE_BAD_REQUEST, "Unable to start docker-compose container.")
UNABLE_TO_STOP_DOCKER_COMPOSE = Result(
    CODE_BAD_REQUEST, "Unable to stop docker-compose container.")
UNABLE_TO_DOWNLOAD_DOCKER_COMPOSE = Result(
    CODE_BAD_REQUEST, "Unable to download docker-compose container.")
UNABLE_TO_PULL_IMAGE = Result(
    CODE_BAD_REQUEST, "Unable to pull image.")
FILE_NOT_FOUND = Result(
    CODE_NOT_FOUND, "FILE NOT FOUND")
IMAGE_IMPORT_FAILURE = Result(
    CODE_UNAUTHORIZED, "FAILED IMAGE IMPORT, IMAGE ALREADY PRESENT")
UNABLE_TO_LOGIN_INTO_DOCKER_REGISTRY = Result(
    CODE_BAD_REQUEST, "Unable to login into docker registry")
UNABLE_TO_LIST_IMAGE_CONTAINERS = Result(
    CODE_BAD_REQUEST, "Unable to list running containers.")
UNABLE_TO_REMOVE_DOCKER_IMAGES = Result(
    CODE_BAD_REQUEST, "Docker Remove operation failed.")
UNABLE_TO_STOP_CONTAINER = Result(
    CODE_BAD_REQUEST, "Unable to stop container.")
UNABLE_TO_FETCH_DOCKER_STATS = Result(
    CODE_BAD_REQUEST, "Unable to fetch container stats.")
UNABLE_TO_DOWNLOAD_APPLICATION_PACKAGE = Result(
    CODE_BAD_REQUEST, "Unable to download application package.")


# Successful result constants
COMMAND_SUCCESS = Result(CODE_OK, "COMMAND SUCCESSFUL")
INSTALL_SUCCESS = Result(CODE_OK, "SUCCESSFUL INSTALL")
PUBLISH_SUCCESS = Result(CODE_OK, "MANIFEST PUBLISH SUCCESSFUL")
CONFIG_LOAD_SUCCESS = Result(CODE_OK, "Configuration load: SUCCESSFUL")
CONFIG_LOAD_FAIL_WRONG_PATH = Result(
    CODE_BAD_REQUEST, 'Configuration load: Invalid configuration load path. The conf file is expected to be under ' + CACHE)
