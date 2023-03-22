"""Unit tests for the utilities module"""

from mock import mock_open, patch
import unittest
from threading import Thread

import cloudadapter.utilities as utilities


class TestWaiter(unittest.TestCase):

    @patch("builtins.open", new_callable=mock_open, read_data="TRUE")
    @patch('os.path.exists', return_value=True)
    @patch('os.path.islink', return_value=False)
    def test_ucc_mode_true(self, mock_islink, mock_exists, mock_open):
        self.assertTrue(utilities.is_ucc_mode())

    @patch("builtins.open", new_callable=mock_open, read_data="FALSE")
    @patch('os.path.exists', return_value=True)
    @patch('os.path.islink', return_value=False)
    def test_ucc_mode_false(self, mock_islink, mock_exists, mock_open):
        self.assertFalse(utilities.is_ucc_mode())

    @patch('os.path.exists', return_value=False)
    @patch('os.path.islink', return_value=False)
    def test_false_when_ucc_mode_file_dne(self, mock_islink, mock_exists):
        self.assertFalse(utilities.is_ucc_mode())

    @patch('os.path.exists', return_value=True)
    @patch('os.path.islink', return_value=True)
    def test_raise_when_ucc_mode_file_is_symlink(self, mock_islink, mock_exists):
        with self.assertRaises(IOError):
            utilities.is_ucc_mode()

    @patch("builtins.open", side_effect=IOError)
    @patch('os.path.exists', return_value=True)
    @patch('os.path.islink', return_value=False)
    def test_raise_when_ucc_file_open_unsuccessful(self, mock_islink, mock_exists, mock_open):
        with self.assertRaises(IOError):
            utilities.is_ucc_mode()

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
