"""
Unit tests for the InbsAdapter class


"""

import unittest

from time import time

from cloudadapter.cloud.adapters.inbs_adapter import InbsAdapter


class TestInbsAdapter(unittest.TestCase):

    def setUp(self) -> None:
        self.CONFIG: dict[str, str] = {
            "hostname": "localhost",
            "port": "50051",
            "node-id": "node_id",
            "token": "token",
        }

        self.inbs_adapter = InbsAdapter(self.CONFIG)

    def test_configure_succeeds(self) -> None:
        self.inbs_adapter.configure(self.CONFIG)
