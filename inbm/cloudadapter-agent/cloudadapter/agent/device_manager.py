"""
Responsible for dealing with messages that manipulate the device

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from ..cloud.adapter_factory import get_adapter_config_filepaths
from ..constants import MESSAGE
from .broker import Broker
from inbm_common_lib.utility import remove_file
import os
import logging
logger = logging.getLogger(__name__)


class DeviceManager:
    """Handles communication between the cloud and the device

    @param broker: (Broker) The broker to use
    """

    def __init__(self, broker: Broker) -> None:
        self._broker = broker

    def shutdown_device(self) -> str:
        """Shutdown the device

        @return: (str) An accompanying message
        """
        self._broker.publish_shutdown()
        return MESSAGE.SHUTDOWN

    def reboot_device(self) -> str:
        """Reboot the device

        @return: (str) An accompanying message
        """
        self._broker.publish_reboot()
        return MESSAGE.REBOOT

    def decommission_device(self) -> str:
        """Decommission the device

        @return: (str) An accompanying message
        """
        logger.info(MESSAGE.DECOMMISSION)

        files_to_remove = get_adapter_config_filepaths()
        for f in files_to_remove:
            try:
                remove_file(f)
            except OSError:
                logger.warn("Failed to remove %s", f)

        self._broker.publish_decommission()

        return MESSAGE.DECOMMISSION
