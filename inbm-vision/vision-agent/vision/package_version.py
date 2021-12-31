# -*- coding: utf-8 -*-
"""
    This module is to check the current vision-agent package installed on IA host system.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from inbm_vision_lib.shell_runner import PseudoShellRunner
from typing import Optional

logger = logging.getLogger(__name__)


def get_version() -> Optional[str]:
    """Helper function for getting version of vision-agent in the system

    @return: version of vision-agent
    """
    logger.debug("")
    cmd = "dpkg-query -W inbm-vision-agent"
    (output, err, code) = PseudoShellRunner.run(cmd)
    if code == 0:
        version = output.rsplit("vision-agent")[-1].strip()
        return version
    else:
        logger.error("{0}".format(err))
        return None
