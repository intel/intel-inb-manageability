"""
    Interface to Node DataHandler class

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class IDataHandler(ABC):
    """Acts as the client in the Command Pattern.  It decides which receiver objects it assigns
    to the command objects and which commands it assigns to the invoker."""

    @abstractmethod
    def register(self) -> None:
        """Add register_command to invoker when node being initialize

        1. Called when Node being initialize  
        2. Create the RegisterCommand object
        4. Add the Command to Invoker

        """

        pass

    @abstractmethod
    def receive_xlink_message(self, message: str) -> None:
        """Receive the message from xlink. It has following flows:

        1. Parse the xml received from node
        2. Determine which command it is
        3. Create the correct Command object
        4. Add the Command to Invoker

        @param message: message received from xlink
        """

        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop the invoker and heartbeat checking timer"""

        pass
