"""
    Factory to create the correct Command object

    # Copyright (C) 2020-2022 Intel Corporation
    # SPDX-License-Identifier: Apache-2.0
"""
from ..ibroker import IBroker
from ..inbc_exception import InbcException
from .command import Command, RestartCommand, QueryCommand
from .ota_command import FotaCommand, SotaCommand, PotaCommand
from .config_command import GetConfigCommand, SetConfigCommand, LoadConfigCommand, AppendConfigCommand

from inbm_common_lib.constants import CONFIG_LOAD, CONFIG_APPEND
from inbm_vision_lib.constants import FOTA, SOTA, POTA, RESTART, QUERY


def create_command_factory(cmd: str, broker: IBroker) -> Command:
    """Creates the concrete command class matching the command given by the user

    @param cmd: command string from user
    @param broker: broker object
    @return Concrete command object
    """
    if cmd == POTA:
        return PotaCommand(broker)
    if cmd == FOTA:
        return FotaCommand(broker)
    if cmd == SOTA:
        return SotaCommand(broker)
    if cmd == RESTART:
        return RestartCommand(broker)
    if cmd == QUERY:
        return QueryCommand(broker)
    if cmd == CONFIG_LOAD:
        return LoadConfigCommand(broker)
    if cmd == 'get':
        return GetConfigCommand(broker)
    if cmd == 'set':
        return SetConfigCommand(broker)
    if cmd == 'append':
        return AppendConfigCommand(broker)

    raise InbcException(f"Unsupported command {cmd}")
