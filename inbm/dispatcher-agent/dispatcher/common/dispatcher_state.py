#!/usr/bin/python
"""
    Central communication agent in the manageability framework responsible
    for issuing commands and signals to other tools/agents

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import builtins
import logging
import os

# pickle is only used to read from a trusted state file
import pickle  # noqa: S403

from typing import Dict, Any, Optional

from .constants import DISPATCHER_STATE_FILE
from ..dispatcher_exception import DispatcherException
from inbm_common_lib.utility import remove_file

logger = logging.getLogger(__name__)


def clear_dispatcher_state() -> None:
    """Deletes the dispatcher state file which was created at start of a previous SOTA"""
    if os.path.exists(DISPATCHER_STATE_FILE):
        logger.debug('Dispatcher state file exists')
        remove_file(DISPATCHER_STATE_FILE)
        logger.debug('Dispatcher state file deleted from disk')
    else:
        logger.debug('Dispatcher state file does not exist')


def is_dispatcher_state_file_exists() -> bool:
    """SOTA leaves a file on disk just after an attempt for SOTA.  If file exists, it means
    reboot was triggered by SOTA attempt.

    @return: True if file exists; otherwise, false.
    """
    if os.path.exists(DISPATCHER_STATE_FILE):
        logger.debug('Dispatcher state file exists')
        return True
    else:
        logger.debug('Dispatcher state file does not exist')
        return False


def consume_dispatcher_state_file(read=False) -> Optional[Dict[str, Any]]:
    """Read dispatcher state file and return state object, clearing state file on success

    @param read: set to True when only file info needs to be read without removing the file
    @return: state object from state file; None on error
    """
    logger.debug("")
    fd = None
    state = None
    try:
        logger.debug("attempting to open file " + str(DISPATCHER_STATE_FILE))
        fd = builtins.open(DISPATCHER_STATE_FILE, 'rb')
        logger.debug("attempting to unpickle from state file")
        # override S301 because we are unpickling from trusted file
        state = pickle.load(fd)  # noqa: S301
        logger.debug("unpickling succeeded")
        logger.debug(f"Disp State file info: {state}")
    except (OSError, pickle.UnpicklingError, AttributeError, FileNotFoundError) as e:
        logger.exception(f"Exception while extracting dispatcher state from disk: {e}")
        raise DispatcherException("Exception while extracting dispatcher state from disk") from e
    finally:
        if fd:
            fd.close()
        if read:
            return state
    clear_dispatcher_state()
    return state


def write_dispatcher_state_to_state_file(state: Dict) -> None:  # pragma: no cover
    """Update state file dictionary with state object

    @param state: state object to use to update state file
    """

    try:
        # if there's already a state file, read it in so we can update it and write back
        if is_dispatcher_state_file_exists():
            with builtins.open(DISPATCHER_STATE_FILE, 'rb') as fd:
                # we are reading from a trusted state file here
                val = pickle.load(fd)  # noqa: S301
                val.update(state)
                state = val
            logger.debug(f"STATE WRITTEN: {state}")
        with open(DISPATCHER_STATE_FILE, 'wb') as fd:
            pickle.dump(state, fd)
    except (OSError, pickle.UnpicklingError, AttributeError) as e:
        logger.exception(f"Exception while saving dispatcher state to disk: {e}")
        raise DispatcherException("Exception while saving dispatcher state to disk") from e
