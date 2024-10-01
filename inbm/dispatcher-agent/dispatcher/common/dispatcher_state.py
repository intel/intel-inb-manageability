#!/usr/bin/python
"""
    Central communication agent in the manageability framework responsible
    for issuing commands and signals to other tools/agents

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import builtins
from datetime import datetime
import logging
import os

# pickle is only used to read from a trusted state file
import pickle  # nosec: B301, B403

from typing import Dict, Any, TypedDict

from .constants import OLD_DISPATCHER_STATE_FILE, NEW_DISPATCHER_STATE_FILE
from ..dispatcher_exception import DispatcherException
from inbm_common_lib.utility import remove_file

logger = logging.getLogger(__name__)


def clear_dispatcher_state() -> None:
    """Deletes the dispatcher state file which was created at start of a previous SOTA.
    
    Check both locations for the file and delete the first one found."""
    if os.path.exists(OLD_DISPATCHER_STATE_FILE):
        logger.debug('Dispatcher state file exists in old location')
        remove_file(OLD_DISPATCHER_STATE_FILE)
        logger.debug('Dispatcher state file deleted from disk')
    elif os.path.exists(NEW_DISPATCHER_STATE_FILE):
        logger.debug('Dispatcher state file exists in new location')
        remove_file(NEW_DISPATCHER_STATE_FILE)
        logger.debug('Dispatcher state file deleted from disk')
    else:
        logger.debug('Dispatcher state file does not exist')


def is_dispatcher_state_file_exists() -> bool:
    """SOTA leaves a file on disk just after an attempt for SOTA.  If file exists, it means
    reboot was triggered by SOTA attempt.

    Check both old and new locations.

    @return: True if file exists; otherwise, false.
    """
    if os.path.exists(OLD_DISPATCHER_STATE_FILE) or os.path.exists(NEW_DISPATCHER_STATE_FILE):
        logger.debug('Dispatcher state file exists')
        return True
    else:
        logger.debug('Dispatcher state file does not exist')
        return False


DispatcherState = TypedDict('DispatcherState', {
    'restart_reason': str,
    'snapshot_num': str,
    'bios_version': str,
    'release_date': datetime,
    'mender-version': str
}, total=False)


def consume_dispatcher_state_file(read: bool = False) -> DispatcherState | None:
    """Read dispatcher state file and return state object, clearing state file on success

    Try old location first, then new location.

    @param read: Set to True to read file info without removing the file
    @return: State object from state file; None on error
    """
    logger.debug("Starting consume_dispatcher_state_file")

    state = None
    state_files = [OLD_DISPATCHER_STATE_FILE, NEW_DISPATCHER_STATE_FILE]

    for state_file in state_files:
        try:
            logger.debug(f"Attempting to open file {state_file}")
            with builtins.open(state_file, 'rb') as fd:
                logger.debug("Attempting to unpickle from state file")
                state = pickle.load(fd)  # nosec
                logger.debug("Unpickling succeeded")
                logger.debug(f"Dispatcher State file info: {state}")
            # Successfully read the state file, no need to try others
            break
        except (OSError, pickle.UnpicklingError, AttributeError, FileNotFoundError) as e:
            logger.exception(f"Exception while extracting dispatcher state from {state_file}: {e}")
            state = None  # Ensure state is None if this attempt fails

    if state is None:
        logger.error("Failed to extract dispatcher state from all state files.")
        raise DispatcherException("Exception while extracting dispatcher state from disk")

    if not read:
        try:
            logger.debug("Clearing dispatcher state files")
            clear_dispatcher_state()
        except Exception as e:
            logger.exception(f"Failed to clear dispatcher state files: {e}")
            # Depending on requirements, you might want to raise or handle this differently

    return state


def write_dispatcher_state_to_state_file(state: DispatcherState) -> None:  # pragma: no cover
    """Update state file dictionary with state object

    @param state: state object to use to update state file
    """

    try:
        # if there's already a state file, read it in so we can update it and write back
        if is_dispatcher_state_file_exists():
            with builtins.open(NEW_DISPATCHER_STATE_FILE, 'rb') as fd:
                # we are reading from a trusted state file here
                val = pickle.load(fd)  # nosec B301
                val.update(state)
                state = val
            logger.debug(f"STATE WRITTEN: {state}")
        with open(NEW_DISPATCHER_STATE_FILE, 'wb') as fd:
            pickle.dump(state, fd)
    except (OSError, pickle.UnpicklingError, AttributeError) as e:
        logger.exception(f"Exception while saving dispatcher state to disk: {e}")
        raise DispatcherException("Exception while saving dispatcher state to disk") from e
