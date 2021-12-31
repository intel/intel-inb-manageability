from telemetry.container_usage import ContainerUsage
from unittest import TestCase
from future import standard_library
standard_library.install_aliases()


class MockTrtl:

    def __init__(self, error):
        self.stats_called = False
        self.error = error

    def stats(self):
        self.stats_called = True
        if self.error:
            return ""
        else:
            return '{"containers":[]}'


class TestContainerUsage(TestCase):

    def test_container_usage_fail(self):
        trtl = MockTrtl(True)
        c = ContainerUsage(trtl)  # type: ignore
        usage = c.get_container_usage()
        self.assertIsNone(usage)

    def test_container_usage_success(self):
        trtl = MockTrtl(False)
        c = ContainerUsage(trtl)  # type: ignore
        usage = c.get_container_usage()
        self.assertEquals(usage, '{"containers":[]}')
