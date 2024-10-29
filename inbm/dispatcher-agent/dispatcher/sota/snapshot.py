"""
    SOTA snapshot class. Creates a snapshot prior to system update.
    
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import time

from abc import ABC, ABCMeta, abstractmethod
from inbm_lib.trtl import Trtl
from typing import Any, Dict, Optional
from inbm_common_lib.shell_runner import PseudoShellRunner
from inbm_common_lib.utility import get_os_version
from inbm_common_lib.constants import UNKNOWN
from .constants import MENDER_FILE_PATH
from .mender_util import read_current_mender_version
from .update_tool_util import update_tool_commit_command
from .rebooter import Rebooter
from ..common import dispatcher_state
from .sota_error import SotaError
from ..dispatcher_exception import DispatcherException
from ..dispatcher_broker import DispatcherBroker

logger = logging.getLogger(__name__)


def mender_commit_command() -> str:  # pragma: no cover
    (out, err, code) = PseudoShellRunner().run(MENDER_FILE_PATH + " -help")
    if "-commit" in out or ((err is not None) and "-commit" in err):
        return "mender -commit"
    else:
        return "mender commit"


class Snapshot(metaclass=ABCMeta):  # pragma: no cover
    """Base class for handling snapshot related task for the system.

    @param trtl: TRTL instance
    @param sota_cmd: SOTA command (update)
    @param snap_num: snapshot number
    @param proceed_without_rollback: Rollback on failure if False; otherwise, rollback.
    @param reboot_device: If True, reboot device on success or failure, otherwise, do not reboot.
    """

    def __init__(self, trtl: Trtl, sota_cmd: str,  snap_num: Optional[str],
                 proceed_without_rollback: bool, reboot_device: bool) -> None:
        self.trtl = trtl
        self.sota_cmd = sota_cmd
        self.snap_num = snap_num
        self.proceed_without_rollback = proceed_without_rollback
        self._reboot_device = reboot_device

    @abstractmethod
    def take_snapshot(self) -> None:
        """Takes a Snapshot through Trtl before running commands.

        if Snapshot fails, checks a configuration agent flag to see if we can proceed without rollback
        or not. If snapshot succeeds, then it sets an instance variable 'snap_num' to proceed.
        """
        pass

    @abstractmethod
    def commit(self) -> int:
        """Generic method. Call when update is complete and everything is working.

        Always remove dispatcher state file.

        @return: result code (0 on success).
        """
        pass

    @abstractmethod
    def recover(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Recover from a failed SOTA.

        Abstract function. Implementations may reboot.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("")
        pass

    @abstractmethod
    def revert(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Revert after second system SOTA boot when we see a problem with startup.

        Implementations may reboot.

        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        pass

    @abstractmethod
    def update_system(self) -> None:
        """If the system supports it, check whether the system was updated, after rebooting.
        """
        pass


class DebianBasedSnapshot(Snapshot):
    """ Snapshot for Debian OS.

        @param trtl: TRTL instance
        @param sota_cmd: SOTA command (update)
        @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
        @param snap_num: snapshot number
        @param proceed_without_rollback: Rollback on failure if False; otherwise, rollback.
        @param reboot_device: If True, reboot device on success or failure, otherwise, do not reboot.
        """

    def __init__(self, trtl: Trtl, sota_cmd: str,
                 dispatcher_broker: DispatcherBroker, snap_num: Optional[str],
                 proceed_without_rollback: bool, reboot_device: bool) -> None:
        super().__init__(trtl, sota_cmd,
                         snap_num, proceed_without_rollback, reboot_device)
        self._dispatcher_broker = dispatcher_broker

    def take_snapshot(self) -> None:
        """Takes a Snapshot through Trtl before running commands.

        if Snapshot fails,
        it checks a configuration agent flag to see if we can proceed without rollback
        or not. If snapshot succeeds, then it sets an instance variable 'snap_num' to proceed.
        """
        logger.debug("")
        self._dispatcher_broker.telemetry(
            f"SOTA Attempting snapshot of system before SOTA {self.sota_cmd}")

        try:
            temp_snapshot_num, err = self.trtl.single_snapshot("sota_" + self.sota_cmd)
            if err:
                raise DispatcherException(err)
            snapshot_num: str = temp_snapshot_num.strip(' \t\n\r')
            if snapshot_num:
                restart_reason = None

                state: dispatcher_state.DispatcherState | None = dispatcher_state.consume_dispatcher_state_file(
                    readonly=True)
                if state:
                    restart_reason = state.get('restart_reason')
                if restart_reason:
                    state = {'snapshot_num': snapshot_num}
                else:
                    state = {'restart_reason': "sota_" + self.sota_cmd,
                             'snapshot_num': snapshot_num}

                dispatcher_state.write_dispatcher_state_to_state_file(state)
        except DispatcherException:
            if self.proceed_without_rollback:
                # Even if we can't take a snapshot, on a subsequent boot we still
                # need dispatcher_state to reflect that we ran a SOTA so we can update
                # logs, perform health check, etc.
                initial_state: dispatcher_state.DispatcherState = (
                    {'restart_reason': "sota_" + self.sota_cmd,
                     'snapshot_num': '0'}
                )
                dispatcher_state.write_dispatcher_state_to_state_file(initial_state)
                self._dispatcher_broker.telemetry(
                    "SOTA snapshot of system failed, will proceed "
                    "without snapshot/rollback feature")
            else:
                raise SotaError(
                    'SOTA will not proceed without snapshot/rollback support')
        else:
            self._dispatcher_broker.telemetry("SOTA snapshot succeeded")
            self.snap_num = snapshot_num

    def _rollback_and_delete_snap(self) -> None:
        """Invokes Trtl to rollback to the snapshot in these conditions:

        a.) After reboot by SOTA, and diagnostic reports bad report for system health
        """
        logger.debug("")
        if self.snap_num and self.snap_num != "0":
            self._dispatcher_broker.telemetry("SOTA attempting rollback")
            rc, err = self.trtl.sota_rollback(self.snap_num)
        else:
            self._dispatcher_broker.telemetry("SOTA rollback skipped")
            return

        if rc == 0:
            self._dispatcher_broker.telemetry("Rollback succeeded")
            self.commit()
        else:
            self._dispatcher_broker.telemetry(
                f"SOTA rollback failed: {err}")

    def commit(self) -> int:
        """Invokes Trtl to delete snapshots in these conditions:

        a.) After reboot by SOTA, and everything works well
        b.) After reboot by SOTA, and diagnostic reports bad report for system health

        Remove dispatcher state file.

        @return: result code (0 on success).
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        err: Optional[str]
        if self.snap_num is None:
            rc, err = 1, 'snap_num is None'
        elif self.snap_num == 0:
            rc, err = 0, 'snap_num is 0 (dummy snapshot); no need to delete'
        else:
            rc, err = self.trtl.delete_snapshot(self.snap_num)
        if err is None:
            err = ''

        if rc == 0:
            self._dispatcher_broker.telemetry("Snapshot cleanup succeeded")
            return rc
        else:
            self._dispatcher_broker.telemetry(
                f"SOTA snapshot delete failed: {err}")
            return rc

    def recover(
            self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Recover from a failed SOTA.

        On Debian-based OSes, we need to rollback and delete the snapshot, and reboot.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        dispatcher_state.clear_dispatcher_state()
        if self.snap_num and self.snap_num != "0":
            self._rollback_and_delete_snap()
            logger.debug("Rebooting to recover from failed SOTA...")
            rebooter.reboot()
        else:
            if self._reboot_device:
                logger.debug(
                    f"Rebooting to recover from failed SOTA...time_to_wait_before_reboot = {str(time_to_wait_before_reboot)}")
                time.sleep(time_to_wait_before_reboot)
                rebooter.reboot()

    def revert(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Revert after second system SOTA boot when we see a problem with startup.

        On Debian-based OSes, we need to rollback, delete snapshot, and reboot.
        If there is no snapshot, the system will not reboot.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        if self.snap_num and self.snap_num != "0":
            self._rollback_and_delete_snap()
            time.sleep(time_to_wait_before_reboot)
            rebooter.reboot()
        else:
            logger.info("No snapshot. Cancel reboot.")

    def update_system(self) -> None:
        """If the system supports it, check whether the system was updated, after rebooting.

        For Debian-based OSes, we perform no checks.
        """
        pass


class WindowsSnapshot(Snapshot):  # pragma: no cover
    """ Snapshot for Windows.

        @param trtl: TRTL instance
        @param sota_cmd: SOTA command (update)
        @param snap_num: snapshot number
        @param proceed_without_rollback: Rollback on failure if False; otherwise, rollback.
        @param reboot_device: If True, reboot device on success or failure, otherwise, do not reboot.
        """

    def __init__(self, trtl: Trtl, sota_cmd: str,  snap_num: Optional[str],
                 proceed_without_rollback: bool, reboot_device: bool) -> None:
        super().__init__(trtl, sota_cmd,
                         snap_num, proceed_without_rollback, reboot_device)

    def take_snapshot(self) -> None:
        """Takes a Snapshot through Trtl before running commands. if Snapshot fails,

        it checks a configuration agent flag to see if we can proceed without rollback
        or not. If snapshot succeeds, then it sets an instance variable 'snap_num' to proceed.
        """
        pass

    def commit(self) -> int:
        """Invokes Trtl to delete snapshots in these conditions:

        a.) After reboot by SOTA, and everything works well
        b.) After reboot by SOTA, and diagnostic reports bad report for system health

        Delete dispatcher state file.

        @return: result code (0 on success).
        """
        dispatcher_state.clear_dispatcher_state()
        return 0

    def recover(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Recover from a failed SOTA. Stub. Not implemented for Windows.

        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        @return: nothing
        """
        logger.debug("")
        pass

    def revert(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Revert after second system SOTA boot when we see a problem with startup.

        Stub for Windows.

        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        pass

    def update_system(self) -> None:
        """If the system supports it, check whether the system was updated, after rebooting.

        Stub for Windows.
        """
        pass


class YoctoSnapshot(Snapshot):
    """ Snapshot for Yocto OS.

    @param trtl: TRTL instance
    @param sota_cmd: SOTA command (update)
    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    @param snap_num: snapshot number
    @param proceed_without_rollback: Rollback on failure if False; otherwise, rollback.
   """

    def __init__(self, trtl: Trtl, sota_cmd: str,
                 dispatcher_broker: DispatcherBroker, snap_num: Optional[str],
                 proceed_without_rollback: bool, reboot_device: bool) -> None:
        super().__init__(trtl, sota_cmd,
                         snap_num, proceed_without_rollback, reboot_device)
        self._dispatcher_broker = dispatcher_broker

    def take_snapshot(self) -> None:
        """This method saves the current mender artifact version info in a dispatcher state file

        @raises SotaError: When failed to create a dispatcher state file
        """
        logger.debug("Yocto take_snapshot")
        self._dispatcher_broker.telemetry(
            "SOTA attempting to create a dispatcher state file before SOTA {}...".
            format(self.sota_cmd))
        try:
            content = read_current_mender_version()
            state: dispatcher_state.DispatcherState
            if dispatcher_state.is_dispatcher_state_file_exists():
                consumed_state = dispatcher_state.consume_dispatcher_state_file(readonly=True)
                restart_reason = None
                if consumed_state:
                    restart_reason = consumed_state.get('restart_reason', None)
                if restart_reason:
                    state = {'mender-version': content}
            else:
                state = (
                    {'restart_reason': "sota",
                     'mender-version': content}
                )
            dispatcher_state.write_dispatcher_state_to_state_file(state)
        except DispatcherException:
            self._dispatcher_broker.telemetry(
                "...state file creation unsuccessful.")
            raise SotaError('Failed to create a dispatcher state file')

        self._dispatcher_broker.telemetry(
            "Dispatcher state file creation successful.")

    def commit(self) -> int:
        """On Yocto, this method runs a Mender commit

        Also, delete dispatcher state file.
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        cmd = mender_commit_command()
        logger.debug("Running Mender commit: " + str(cmd))
        (out, err, code) = PseudoShellRunner().run(cmd)

        return code

    def recover(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Recover from a failed SOTA.

        On Yocto with Mender, no action is required other than deleting the
        state file and rebooting.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        time.sleep(time_to_wait_before_reboot)
        rebooter.reboot()

    def revert(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Revert after second system SOTA boot when we see a problem with startup.

        On Ubuntu, we need to rollback, delete snapshot, and reboot.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("time_to_wait_before_reboot = " + str(time_to_wait_before_reboot))
        dispatcher_state.clear_dispatcher_state()
        time.sleep(time_to_wait_before_reboot)
        rebooter.reboot()

    def update_system(self) -> None:
        """If the system supports it, check whether the system was updated, after rebooting.

        For Yocto, we compare the dispatcher state file to current system information
        (from a mender command defined in a constant)
        """

        logger.debug("attempting to get dispatcher state from state file")
        state = dispatcher_state.consume_dispatcher_state_file()
        if state is not None and 'mender-version' in state:
            logger.debug("got mender-version from state: " + str(state['mender-version']))
            version = read_current_mender_version()
            current_mender_version = version
            previous_mender_version = state['mender-version']

            if current_mender_version == previous_mender_version:
                raise SotaError(
                    f"Requested update version is the same as version currently installed. {current_mender_version}")
            else:
                logger.debug("success; mender version changed")

        else:
            raise SotaError(
                f"'mender-version' not in state or state is not available. state = {str(state)}")


class TiberOSSnapshot(Snapshot):
    """ Snapshot for TiberOS.

    @param trtl: TRTL instance
    @param sota_cmd: SOTA command (update)
    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    @param snap_num: snapshot number
    @param proceed_without_rollback: Rollback on failure if False; otherwise, rollback.
   """

    def __init__(self, trtl: Trtl, sota_cmd: str,
                 dispatcher_broker: DispatcherBroker, snap_num: Optional[str],
                 proceed_without_rollback: bool, reboot_device: bool) -> None:
        super().__init__(trtl, sota_cmd,
                         snap_num, proceed_without_rollback, reboot_device)
        self._dispatcher_broker = dispatcher_broker

    def take_snapshot(self) -> None:
        """This method saves the current TiberOS artifact version info in a dispatcher state file

        @raises SotaError: When failed to create a dispatcher state file
        """
        logger.debug("TiberOS take_snapshot")
        self._dispatcher_broker.telemetry(
            "SOTA attempting to create a dispatcher state file before SOTA {}...".
            format(self.sota_cmd))
        try:
            content = get_os_version()
            if content == UNKNOWN:
                raise SotaError("Failed to get os version.")
            state: dispatcher_state.DispatcherState
            if dispatcher_state.is_dispatcher_state_file_exists():
                consumed_state = dispatcher_state.consume_dispatcher_state_file(readonly=True)
                restart_reason = None
                if consumed_state:
                    restart_reason = consumed_state.get('restart_reason', None)
                if restart_reason:
                    state = {'tiberos-version': content}
            else:
                state = (
                    {'restart_reason': "sota",
                     'tiberos-version': content}
                )
            dispatcher_state.write_dispatcher_state_to_state_file(state)
        except (DispatcherException, SotaError) as err:
            self._dispatcher_broker.telemetry(
                "...state file creation unsuccessful.")
            raise SotaError('Failed to create a dispatcher state file. Error: ', err)

        self._dispatcher_broker.telemetry(
            "Dispatcher state file creation successful.")

    def commit(self) -> int:
        """On TiberOS, this method runs a UT commit command

        Also, delete dispatcher state file.
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        code = update_tool_commit_command()

        return code

    def recover(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Recover from a failed SOTA.

        On TiberOS, no action is required other than deleting the
        state file and rebooting.
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("")
        dispatcher_state.clear_dispatcher_state()
        time.sleep(time_to_wait_before_reboot)
        rebooter.reboot()

    def revert(self, rebooter: Rebooter, time_to_wait_before_reboot: int) -> None:
        """Revert after second system SOTA boot when we see a problem with startup.

        On TiberOS, we just reboot without commit
        @param rebooter: Object implementing reboot() method
        @param time_to_wait_before_reboot: If we are rebooting, wait this many seconds first.
        """
        logger.debug("time_to_wait_before_reboot = " + str(time_to_wait_before_reboot))
        dispatcher_state.clear_dispatcher_state()
        time.sleep(time_to_wait_before_reboot)
        rebooter.reboot()

    def update_system(self) -> None:
        """If the system supports it, check whether the system was updated, after rebooting.

        For TiberOS, we compare the image's version stored in dispatcher state file and current os version.
        """

        logger.debug("attempting to get dispatcher state from state file")
        state = dispatcher_state.consume_dispatcher_state_file()
        if state is not None and 'tiberos-version' in state:
            logger.debug("got tiberos-version from state: " + str(state['tiberos-version']))
            version = get_os_version()
            current_tiberos_version = version
            previous_tiberos_version = state['tiberos-version']

            if current_tiberos_version == previous_tiberos_version:
                raise SotaError(
                    f"Requested update version is the same as previous version installed. VERSION: "
                    f"{current_tiberos_version}")
            else:
                logger.debug("success; tiberos version changed")

        else:
            raise SotaError(
                f"'tiberos-version' not in state or state is not available. state = {str(state)}")
