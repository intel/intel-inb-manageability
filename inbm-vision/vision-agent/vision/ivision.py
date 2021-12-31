"""
    Interface to Vision class

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


from typing import Optional
from vision.broker import Broker
from .node_communicator.node_connector import NodeConnector
from abc import ABC, abstractmethod


class IVision(ABC):
    """Interface for the Vision class"""

    @abstractmethod
    def get_node_connector(self) -> Optional[NodeConnector]:
        """ Get Node Connector used in vision-agent

        @return: NodeConnector object
        """
        pass

    @abstractmethod
    def get_broker(self) -> Optional[Broker]:
        """Broker callback"""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop xlink manager, broker and data_handler"""
        pass
