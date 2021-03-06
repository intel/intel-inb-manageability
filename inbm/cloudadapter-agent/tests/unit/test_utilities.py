"""
Unit tests for the utilities module


"""


import unittest
from threading import Thread

import cloudadapter.utilities as utilities


class TestWaiter(unittest.TestCase):

    def test_wait_succeeds(self):
        waiter = utilities.Waiter()

        thread = Thread(target=waiter.wait)
        thread.daemon = True
        thread.start()
        thread.join(0.5)

        assert thread.isAlive()

    def test_reset_succeeds(self):
        waiter = utilities.Waiter()

        thread = Thread(target=waiter.wait)
        thread.daemon = True
        thread.start()

        waiter.finish()
        waiter.reset()

        thread = Thread(target=waiter.wait)
        thread.daemon = True
        thread.start()
        thread.join(0.5)

        assert thread.isAlive()

    def test_finish_with_synchronize_succeeds(self):
        waiter = utilities.Waiter()

        thread = Thread(target=waiter.wait)
        thread.daemon = True
        thread.start()

        waiter.finish()
        thread.join(1)

        assert not thread.isAlive()

    def test_finish_with_value_succeeds(self):
        waiter = utilities.Waiter()

        result = []

        def worker():
            result.append(waiter.wait())

        thread = Thread(target=worker)
        thread.daemon = True
        thread.start()

        waiter.finish(1)
        thread.join(1)

        assert len(result) == 1 and result[0] == 1


class TestMakeThreaded(unittest.TestCase):

    def test_make_threaded_succeeds(self):

        def blocks():
            while True:
                pass

        def test_threaded():
            utilities.make_threaded(blocks)()

        thread = Thread(target=test_threaded)
        thread.daemon = True
        thread.start()

        thread.join(1)

        assert not thread.isAlive()
