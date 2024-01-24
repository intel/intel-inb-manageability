"""
    Agent responsible for application over the air installs
    and packages.

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
from typing import Any, Optional, Mapping

from inbm_common_lib.exceptions import UrlSecurityException

from dispatcher.common.result_constants import COMMAND_SUCCESS
from dispatcher.config_dbs import ConfigDbs
from ..dispatcher_broker import DispatcherBroker
from .factory import get_app_instance
from .aota_error import AotaError
from .cleaner import cleanup_repo
from ..update_logger import UpdateLogger

logger = logging.getLogger(__name__)


class AOTA:
    """Thread which is responsible for AOTA updates

    @param dispatcher_broker: DispatcherBroker object used to communicate with other INBM services
    @param parsed_manifest: Parsed parameters from manifest
    @param dbs: ConfigDbs.{ON, OFF, WARN}
    """

    def __init__(self,  dispatcher_broker: DispatcherBroker,
                 parsed_manifest: Mapping[str, Optional[Any]], dbs: ConfigDbs,
                 update_logger: UpdateLogger) -> None:
        # security assumption: parsed_manifest is already validated
        self._dispatcher_broker = dispatcher_broker
        self._cmd = parsed_manifest['cmd']
        self._app_type = parsed_manifest['app_type']

        if self._app_type is None:
            raise AotaError("missing application type for AOTA")
        self._app_instance = get_app_instance(
            app_type=self._app_type,
            dispatcher_broker=self._dispatcher_broker,
            parsed_manifest=parsed_manifest,
            dbs=dbs,
            update_logger=update_logger)

    def run(self) -> None:
        """Run command checks the type of command triggered and then installs the file
        based on the command specified

        @raise: AotaError : on failure with error string
        """
        try:
            if self._cmd is None:
                raise AotaError("no cmd given for AOTA")
            self._app_instance.verify_command(self._cmd)
            if self._cmd == "import":
                self._cmd = "import_image"

            app_method = getattr(self._app_instance, self._cmd)
            app_method()
            self._dispatcher_broker.telemetry(
                f'AOTA {self._app_type} {self._cmd} {COMMAND_SUCCESS}')
            self._app_instance.cleanup()
        except (AotaError, UrlSecurityException) as e:
            err = f"AOTA {self._app_type} {self._cmd} FAILED: {e}"
            if self._app_instance.repo_to_clean_up and self._app_instance.resource:
                cleanup_repo(self._app_instance.repo_to_clean_up, self._app_instance.resource)
            self._dispatcher_broker.telemetry(err)
            raise AotaError(err)
