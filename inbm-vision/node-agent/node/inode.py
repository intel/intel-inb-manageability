"""
    Interface to Node class

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from typing import Optional

import logging
from node.broker import Broker
from node.xlink_manager import XlinkManager
from abc import ABC, abstractmethod
from node.idata_handler import IDataHandler

logger = logging.getLogger(__name__)


class INode(ABC):
    """Interface for the Node class"""

    @abstractmethod
    def start(self) -> None:
        """Start xlink_manager"""
        pass

    @abstractmethod
    def initialize(self, broker: Broker, xlink_manager: XlinkManager, data_handler: IDataHandler) -> None:
        pass

    @abstractmethod
    def get_xlink(self) -> Optional[XlinkManager]:
        """xink_manager callback """
        pass

    @abstractmethod
    def get_broker(self) -> Optional[Broker]:
        """Broker callback"""
        pass

    def get_data_handler(self) -> Optional[IDataHandler]:
        """Data Handler callback"""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop xlink manager, broker and data_handler"""
        pass
