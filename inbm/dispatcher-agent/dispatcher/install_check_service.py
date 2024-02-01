"""
    Install check service

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging

from typing import Optional, Union

from dispatcher.dispatcher_broker import DispatcherBroker

from .command import Command
from .dispatcher_exception import DispatcherException

logger = logging.getLogger(__name__)


class InstallCheckService:
    def __init__(self, broker: DispatcherBroker) -> None:
        self._broker = broker

    def install_check(self, size: Union[float, int], check_type: Optional[str] = None) -> None:
        """Perform pre install checks via the diagnostic agent. Send a command <pre_ota_check> to
        diagnostic agent which checks [cloud agent, cloud, memory, storage, battery]

        @param size: size of the install package
        @param check_type : String representation of checks
        eg: check_type='check_storage'..could later be extended to other types
        """

        # Create command object for pre install check
        cmd = Command(check_type, self._broker) if check_type else Command(
            'install_check', self._broker)

        cmd.execute()

        if cmd.log_info != "":
            logger.info(cmd.log_info)
        if cmd.log_error != "":
            logger.error(cmd.log_error)

        if cmd.response is None:
            self._broker.telemetry('Install check timed out. Please '
                                   'check health of the diagnostic agent')
            raise DispatcherException('Install check timed out')

        if cmd.response['rc'] == 0:
            self._broker.telemetry('Command: {} passed. Message: {}'
                                   .format(cmd.command, cmd.response['message']))
            logger.info('Install check passed')

        else:
            self._broker.telemetry('Command: {} failed. Message: {}'
                                   .format(cmd.command, cmd.response['message']))
            raise DispatcherException('Install check failed')
