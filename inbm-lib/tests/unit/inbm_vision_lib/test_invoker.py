from unittest import TestCase
from mock import Mock, patch, MagicMock
import threading
from time import sleep
from inbm_vision_lib.invoker import Invoker


class TestInvoker(TestCase):

    @patch('threading.Thread.start')
    def setUp(self, t_start):
        self.invoker = Invoker(10)
        self.mock_command = Mock()
        t_start.assert_called_once()

    # @patch('threading.Thread.start')
    def test_add_command(self):
        self.mock_command.get_name = MagicMock(return_value="Mock_Command")
        self.invoker.add(self.mock_command)
        # t_start.assert_called_once()
        self.assertFalse(self.invoker.command_queue.empty())

    # @patch('threading.Thread.start')
    def test_add_command_queue_size_full(self):
        for i in range(self.invoker.command_queue.maxsize + 1):
            self.mock_command.get_name = MagicMock(return_value="Mock_Command")
            self.invoker.add(self.mock_command)
       # t_start.assert_called_once()
        self.assertTrue(self.invoker.command_queue.full())

    def test_invoker_handle_command(self):
        self.mock_command.get_name = MagicMock(return_value="Mock_Command")
        self.mock_command.execute = MagicMock(return_value="Mock_Command")
        self.invoker.add(self.mock_command)
        self.invoker._handle_command()
        self.mock_command.execute.assert_called_once()


    def test_run_invoker(self):
        def stop_invoker():
            sleep(1)
            self.invoker.running = False

        self.mock_command.get_name = MagicMock(return_value="Mock_Command")
        self.mock_command.execute = MagicMock(return_value="Mock_Command")
        self.invoker.add(self.mock_command)
        thread = threading.Thread(target=stop_invoker)
        thread.daemon = True
        thread.start()
        self.invoker.run()

    @patch('threading.Thread.start')
    def test_stop_invoker(self, t_start):
        self.invoker.stop()
