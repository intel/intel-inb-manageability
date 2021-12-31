# -*- coding: utf-8 -*-
"""
    This module is to get the unique MAC address of host system.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from inbm_vision_lib.shell_runner import PseudoShellRunner
from typing import Optional
import platform
import psutil
from socket import AddressFamily
import re

logger = logging.getLogger(__name__)


def get_mac_address() -> Optional[str]:
    """Helper function for getting MAC address in the system

    @return: MAC address of the system
    """
    logger.debug("Looking for best MAC address...")
    return _choose_best_mac_address(AddressFamily.AF_LINK) if platform.system() == 'Windows' else _choose_best_mac_address(AddressFamily.AF_PACKET)


def _choose_best_mac_address(address_family: AddressFamily) -> Optional[str]:
    ifaces = psutil.net_if_addrs()
    for iface in ifaces:
        logger.debug(f"Considering {iface}...")
        if iface == "lo" or re.match(r"loopback", iface, re.I):
            logger.debug("Rejecting loopback interface")
        else:
            for addr in ifaces[iface]:
                if addr.family == address_family:
                    logger.debug(
                        f"Accepting {iface} address {addr.address} of family {addr.family}")
                    return addr.address
        logger.debug("Nope!")
    logger.error(f"Cannot find acceptable network interface of family {address_family}")
    return None
