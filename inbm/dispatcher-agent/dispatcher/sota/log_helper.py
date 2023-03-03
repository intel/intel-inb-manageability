"""
    SOTA logging utilities

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
from typing import Optional

from inbm_common_lib.utility import get_canonical_representation_of_path

from .constants import CLOUD, FILE, FAILED
from .command_list import CommandList
from ..dispatcher_callbacks import DispatcherCallbacks

logger = logging.getLogger(__name__)


def get_log_destination(manifest_log_to_file: Optional[str], manifest_sota_cmd: Optional[str]) -> str:
    """Find out what kind of logging flag the command has

    Whether FILE or CLOUD
    @param manifest_log_to_file The log to file parameter from the SOTA manifest
    @param manifest_sota_cmd The cmd parameter from the SOTA manifest
    @return: Either "FILE" or "CLOUD"
    """
    logger.debug("")

    return FILE if _is_valid_yes_value(manifest_log_to_file) or manifest_sota_cmd == "upgrade" \
        else CLOUD


def log_command_error(cmd: CommandList.CommandObject, cmd_index: int, err: Optional[str], output: str, log_file: Optional[str],
                      log_destination: str, dispatcher_callbacks: DispatcherCallbacks) -> None:
    """TODO figure out what this method does or split into multiple

    @param cmd: command object that failed
    @param cmd_index: current index
    @param err: error message
    @param output: output message
    @param log_file: file name
    @param log_destination: Log to FILE or CLOUD?
    @param dispatcher_callbacks: A reference to the main Dispatcher instance.
    """
    logger.debug("")
    file_err = ""
    if log_destination == FILE and log_file is not None:
        logger.debug("logging to file")
        with open(get_canonical_representation_of_path(log_file)) as f:
            for line in f:
                file_err = file_err + ", " + line
        logger.debug("")
    msg = "{}. Command {} failed with Error: {}".format(
        cmd_index, cmd, err or output or file_err)
    logger.debug(msg)
    dispatcher_callbacks.broker_core.telemetry(msg)
    cmd.err.append(err or output or file_err)
    cmd.status = FAILED


def _is_valid_yes_value(x: Optional[str]) -> bool:
    """Compare parameter x to a set of valid 'yes' strings

    @param x: value to check
    @return: True if x is in the valid set; otherwise False
    """
    return x in ["Yes", "Y", "y", "yes", "YES"]
