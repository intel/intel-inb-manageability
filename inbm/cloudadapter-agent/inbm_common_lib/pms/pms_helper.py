"""
    Class to send the request to pms service, e.g. reset device

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""

import logging
import sys
from typing import Optional
import json

logger = logging.getLogger(__name__)


class PmsException(Exception):
    """Class exception Module."""
    pass


class PMSHelper(object):
    """Helper class to send request to PMS service through PMS library"""

    def __init__(self) -> None:
        pass

    def _import_pms_library(self) -> None:
        """Import PMS Python library from /usr/lib"""
        sys.path.insert(0, "/usr/lib/")
        try:
            import libPmsPython  # type: ignore
        except (ImportError, ModuleNotFoundError) as error:
            raise PmsException("Unable to locate PMS Python library")

    def reset_device(self, sw_device_id: str) -> None:
        """Reset device based on provided device id

        @param sw_device_id: xlink sw device id
        @return: True if reset successful; False if reset failed
        """
        self._import_pms_library()
        from libPmsPython import PmsReset, PmsConnection, Status
        conn = PmsConnection()
        if not conn.Connect():
            raise PmsException("PMS Daemon connection failed.")

        pms_reset = PmsReset(conn)
        status = pms_reset.ResetRequest(int(sw_device_id))
        if status == Status.Success:
            logger.debug("Reset: {0} success.".format(sw_device_id))
        else:
            raise PmsException(f'Reset: {sw_device_id} failed with status: {status}.')
        conn.Disconnect()

    def get_rm_telemetry(self) -> str:
        """Calls PMS telemetry API

        @return: Resource Monitor device telemetry logs 
        """
        self._import_pms_library()
        from libPmsPython import  PmsTelemetry, PmsConnection, PmsConnectionType

        conn = PmsConnection()
        if not conn.Connect(PmsConnectionType.RM_DAEMON):
            raise PmsException("RM Daemon connection failed")
        
        pms_telemetry = PmsTelemetry(conn)

        try:
            metrics = pms_telemetry.GetMetrics()
            json_output = json.loads(metrics)
            conn.Disconnect()
            for key,value in json_output.items():
                if len(value) and key == 'Device':
                    return str(value)
            return "Unable to collect Resource Monitor device telemetry logs"
        except Exception as err:
            raise PmsException("Resource Monitor Telemetry Logs Error : {}".format(err))
