from unittest import TestCase
from time import sleep

from diagnostic.repeating_timer import RepeatingTimer


def hello() -> None:
    print('Hello World!')


class TestRepeatingTimer(TestCase):

    def test_timer(self) -> None:
        t = RepeatingTimer(1, hello)
        t.start()
        sleep(3)
        t.stop()
        self.assertIsNotNone(t)
