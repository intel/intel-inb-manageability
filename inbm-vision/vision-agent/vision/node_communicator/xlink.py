""""
    A xlink struct to store the xlink object information.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

from abc import ABC
from typing import Optional, Union
from inbm_vision_lib.xlink.ixlink_wrapper import IXlinkWrapper
from inbm_vision_lib.xlink.xlink_wrapper import XlinkWrapper


class IXlink(ABC):
    """IXlink interface

    @param xlink_wrapper: corresponding XLink wrapper to call Xlink API
    @param channel_id: channel id assigned to xlink
    @param node_id: corresponding node agent connected with this xlink
    """

    def __init__(self, xlink_wrapper: IXlinkWrapper, channel_id: int, node_id: str) -> None:
        self.xlink_wrapper = xlink_wrapper
        self.channel_id = channel_id
        self.node_id = node_id


class XlinkSecured(IXlink):
    """Concrete Xlink Secured class

    @param xlink_wrapper: Concrete wrapper class for secured xlink
    @param channel_id: channel id assigned to xlink
    @param node_id: corresponding node agent connected with this xlink
    """

    def __init__(self, xlink_wrapper: IXlinkWrapper, channel_id: int, node_id: str) -> None:
        super().__init__(xlink_wrapper, channel_id, node_id)


class Xlink(IXlink):
    """Concrete Xlink Unsecured class

    @param xlink_wrapper: Concrete wrapper class for unsecured xlink
    @param channel_id: channel id assigned to xlink
    @param node_id: corresponding node agent connected with this xlink
    """

    def __init__(self, xlink_wrapper: IXlinkWrapper, channel_id: int, node_id: str) -> None:
        super().__init__(xlink_wrapper, channel_id, node_id)


def _xlink_factory(xlink_wrapper: IXlinkWrapper, is_secure: bool, channel_id: int, node_id: str) -> IXlink:
    return XlinkSecured(xlink_wrapper, channel_id, node_id) if is_secure else Xlink(xlink_wrapper, channel_id, node_id)


class XlinkPublic(object):
    """Xlink Public object information.

    @param xlink_wrapper: corresponding XLink wrapper to call Xlink API
    @param xlink_pcie_dev_id: xlink pcie device id
    """

    def __init__(self, xlink_wrapper: Union[IXlinkWrapper], xlink_pcie_dev_id: int, node_id: Optional[str]) -> None:
        self.xlink_wrapper = xlink_wrapper
        self.xlink_pcie_dev_id = xlink_pcie_dev_id
        self.node_id = node_id
