"""
Abstract base class used by all high level messaging objects.
Messengers are responsible for creating a properly formatted payload,
then ensuring their successful publish to the cloud.

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from datetime import datetime
from typing import Optional
import abc


class Messenger(metaclass=abc.ABCMeta):  # pragma: no cover

    @abc.abstractmethod
    def publish(self, key: str, value: str, time: Optional[datetime] = None) -> None:
        """Publish a key/value pair to the given connection

        @param key:       (str) Data key to publish
        @param value:     (str) Data value to publish
        @param time: (datetime) Time of the publish to use
        @exception PublishError: If publishing fails
        """
        pass
