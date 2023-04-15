"""
    SOTA command utilities

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging

from inbm_common_lib.shell_runner import PseudoShellRunner
from typing import List, Optional, Tuple
from .command_list import CommandList
from .log_helper import log_command_error
from .constants import FAILED, LOGPATH, SUCCESS
from ..dispatcher_callbacks import DispatcherCallbacks

logger = logging.getLogger(__name__)


def run_commands(log_destination: str, cmd_list: List[CommandList.CommandObject], dispatcher_callbacks: DispatcherCallbacks) -> None:
    """Runs all commands to perform SOTA operation.

    @param log_destination: log file destination 
    @param cmd_list: list of commands to run
    @param dispatcher_callbacks: reference back to Dispatcher object
    """
    logger.debug("")

    if cmd_list:
        for cmd in cmd_list:
            cmd_index = cmd_list.index(cmd)
            msg = "{}. SOTA Internally Running command: {}".format(cmd_index + 1, str(cmd))
            dispatcher_callbacks.broker_core.telemetry(msg)
            logger.debug(msg)

            output, err, code, abs_log_path = \
                _run_command(cmd=cmd, log_destination=log_destination)

            if code != 0:
                log_command_error(
                    cmd=cmd,
                    cmd_index=cmd_index + 1,
                    err=err,
                    output=output,
                    log_file=abs_log_path,
                    log_destination=log_destination,
                    dispatcher_callbacks=dispatcher_callbacks)
                _skip_remaining_commands(cmd_list, cmd_index, dispatcher_callbacks)
                break

            if log_destination == 'CLOUD':
                dispatcher_callbacks.broker_core.telemetry(
                    "{}. Command {} completed with Log: {}".format(cmd_index + 1, cmd, output))
            elif log_destination == 'FILE':
                dispatcher_callbacks.broker_core.telemetry("{}. Command {} completed, but will log instead to file: "
                                                           "{}".format(cmd_index + 1, cmd, abs_log_path))
            cmd.status = SUCCESS


def get_command_status(cmd_list: List) -> str:
    """Collates results from all internal to determine final sota command outcome

    @return: 'Success' if all commands pass or 'Failure' if any command fails
    """
    logger.debug("")
    if cmd_list:
        for cmd in cmd_list:
            status = FAILED if cmd.status in ('Not Executed', 'Failed', 'Skipped') else SUCCESS
            if status == FAILED:
                logger.debug("Failed executing command: {}".format(str(cmd)))
                break
        return status
    else:
        logger.debug("No commands")
        return FAILED


def print_execution_summary(cmd_list: List, dispatcher_callbacks: DispatcherCallbacks) -> None:
    """Prints a summary of the commands executed at the end of the SOTA process

    @param cmd_list: Array of commands to run.
    @param dispatcher_callbacks: DispatcherCallbacks instance
    """
    logger.debug("")

    summary = ['Summary of Commands: '] if cmd_list else \
        ['Summary of Commands: Nothing to execute']

    for cmd in cmd_list:
        summary. \
            append("Command: {}  status: {}  errors: {}".
                   format(str(cmd), cmd.get_status(), ','.join(cmd.get_errors())))
    dispatcher_callbacks.broker_core.telemetry(','.join(summary))


def _run_command(cmd: CommandList.CommandObject, log_destination: str) -> Tuple[str, Optional[str], int, Optional[str]]:
    logger.debug("")
    return PseudoShellRunner.run_with_log_path(str(cmd), LOGPATH) if \
        log_destination == "FILE" else PseudoShellRunner.run_with_log_path(str(cmd), log_path=None)


def _skip_remaining_commands(cmd_list: List, current_failed_index: int, dispatcher_callbacks: DispatcherCallbacks) -> None:
    """This will skip other processes in the queue if the current one fails"""
    logger.debug("")
    if current_failed_index == (len(cmd_list) - 1):
        dispatcher_callbacks.broker_core.telemetry("No processes to skip")
    else:
        dispatcher_callbacks.broker_core.telemetry(
            "All other processes in the SOTA queue will be skipped")
        for cmd in cmd_list[current_failed_index + 1:]:
            cmd.status = "Skipped"
            cmd.err.append("Skipped because of command {}".format(current_failed_index + 1))
