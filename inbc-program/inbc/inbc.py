"""Command-line INBC tool to invoke Software update on the device with manageability framework.

Copyright (C) 2020-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""

import logging
import sys
import signal
import itertools
from typing import Any
from time import sleep
from inbc import shared
from inbc.broker import Broker
from inbc.parser import ArgsParser
from inbc.inbc_exception import InbcException, InbcCode

from inbm_vision_lib.request_message_constants import *

logger = logging.getLogger(__name__)


class Inbc(object):
    """Initialize the command-line utility tool.
    @param parsed_args: arguments from the user
    @param cmd_type: command type from the user
    @param tls: TLS activated if true; otherwise, not activated
    """

    def __init__(self, parsed_args: Any, cmd_type: str, tls: bool = True) -> None:
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

        self._broker = Broker(cmd_type, parsed_args, tls)
        print("INBC command-line utility tool")

    def stop(self):
        self._broker.stop_broker()


def _sig_handler(signo, _) -> None:
    if signo in (signal.SIGINT, signal.SIGTERM):
        shared.running = False


def catch_termination_via_systemd() -> None:
    """Register with systemd for termination."""
    signal.signal(signal.SIGTERM, _sig_handler)


def catch_ctrl_c_from_user() -> None:
    """Terminate on control-c from user."""
    signal.signal(signal.SIGINT, _sig_handler)


if __name__ == "__main__":
    try:
        catch_ctrl_c_from_user()
        catch_termination_via_systemd()
        args_parse = ArgsParser()
        args = args_parse.parse_args(sys.argv[1:])
        if not len(vars(args)):
            args = args_parse.parse_args(["None"])
        inbc = Inbc(args, sys.argv[1])
        spinning = itertools.cycle(['|', '/', '-', '\\'])
        while shared.running:
            sys.stdout.write(next(spinning))
            sys.stdout.flush()
            sleep(0.1)
            sys.stdout.write('\r')
        inbc.stop()
        sys.exit(shared.exit_code)
    except InbcException as error:
        logging.error(error)
        if inbc:
            inbc.stop()
        sys.exit(1)
