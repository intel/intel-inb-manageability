"""
    Different command object will be created according to different request.
    Each concrete classes have different execute method for different purpose.

    @copyright: Copyright 2019-2022 Intel Corporation All Rights Reserved.
    @license: Intel, see licenses/LICENSE for more details.
"""

import logging

from typing import Optional, List, Dict, Union, Any

from .command import Command
from ..broker import Broker

logger = logging.getLogger(__name__)


class SendTelemetryResponseCommand(Command):

    """SendTelemetryResponseCommand Concrete class

    @param nid: id of node that sent response
    @param broker: instance of Broker object
    @param result: Telemetry result to send back to cloud via MQTT
    """

    def __init__(self, nid: str, broker: Optional[Broker], result: Dict[str, str]) -> None:
        super().__init__(nid)
        self.broker = broker
        self.result = result

    def execute(self) -> None:
        """Send telemetry response message through broker"""
        # TODO: need to confirm the manifest format to be sent as telemetry message
        # message_to_send = ""
        logger.debug('Execute SendTelemetryResponseCommand.')
        if self.broker:
            self.broker.publish_telemetry_response(self._nid, self.result)


class SendTelemetryEventCommand(Command):

    """SendTelemetryEventCommand Concrete class

    @param nid: id of node that sent response
    @param broker: instance of Broker object
    @param message: Telemetry event to send back to cloud via MQTT
    """

    def __init__(self, nid: str, broker: Optional[Broker], message: Union[Any, List[str]]) -> None:
        super().__init__(nid)
        self.broker = broker
        self.message = message

    def execute(self) -> None:
        """Send telemetry event message through broker"""
        logger.debug('Execute SendTelemetryEventCommand.')
        if self.broker:
            m = 'id={0}-{1}'.format(self._nid, self.message)
            self.broker.publish_telemetry_event(self._nid, m)


class SendXlinkStatusCommand(Command):
    def __init__(self, nid: str, broker: Optional[Broker], status: str) -> None:
        super().__init__(nid)
        self.broker = broker
        self.status = status

    def execute(self) -> None:
        """Send telemetry response message through broker"""
        # TODO: need to confirm the manifest format to be sent as telemetry message
        # message_to_send = ""
        logger.debug('Execute SendXlinkStatusCommand.')
        if self.broker:
            self.broker.publish_xlink_status(self._nid, self.status)
