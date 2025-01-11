import unittest
from unittest.mock import patch, mock_open, MagicMock

import dbus

from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.device_manager.power_state import (
    _is_system_sleeping, _get_sleep_state, get_current_power_state
)

class TestPowerStateMethods(unittest.TestCase):

    @patch('dbus.SystemBus')
    def test_is_system_sleeping_true(self, mock_system_bus):
        mock_interface = MagicMock()
        mock_interface.Get.return_value = True
        mock_proxy = MagicMock()
        mock_proxy.get_object.return_value = mock_interface
        mock_system_bus.return_value.get_object.return_value = mock_proxy

        sleep_state = _is_system_sleeping()
        self.assertTrue(sleep_state)

    @patch('dbus.SystemBus')
    def test_is_system_sleeping_false(self, mock_system_bus):
        mock_interface = MagicMock()
        mock_interface.Get.return_value = False
        mock_proxy = MagicMock()
        mock_system_bus.return_value.get_object.return_value = mock_proxy
        with patch('dbus.Interface', return_value=mock_interface):
            sleep_state = _is_system_sleeping()
            self.assertFalse(sleep_state)

    @patch('dbus.SystemBus')
    def test_is_system_sleeping_dbus_exception(self, mock_system_bus):
        mock_system_bus.side_effect = dbus.DBusException('DBus error')

        with self.assertRaises(DispatcherException) as context:
            _is_system_sleeping()
        self.assertIn('Failed to get sleep state: DBus error', str(context.exception))

    @patch('builtins.open', new_callable=mock_open, read_data='freeze mem disk')
    def test_get_sleep_state_success(self, mock_file):
        mock_file.side_effect = [
            mock_open(read_data='freeze mem disk').return_value,
            mock_open(read_data='[s2idle] deep').return_value
        ]
        states, current_mem_sleep_state = _get_sleep_state()
        self.assertEqual(states, ['freeze', 'mem', 'disk'])
        self.assertEqual(current_mem_sleep_state, 's2idle')

    @patch('builtins.open', new_callable=mock_open, read_data='freeze mem disk')
    def test_get_sleep_state_no_brackets(self, mock_file):
        mock_file.side_effect = [
            mock_open(read_data='freeze mem disk').return_value,
            mock_open(read_data='s2idle deep').return_value
        ]
        states, current_mem_sleep_state = _get_sleep_state()
        self.assertEqual(states, ['freeze', 'mem', 'disk'])
        self.assertIsNone(current_mem_sleep_state)

    @patch('builtins.open', new_callable=mock_open, read_data='freeze mem disk')
    def test_get_sleep_state_file_not_found(self, mock_file):
        mock_file.side_effect = FileNotFoundError
        states, current_mem_sleep_state = _get_sleep_state()
        self.assertEqual(states, [])
        self.assertIsNone(current_mem_sleep_state)

    @patch('builtins.open', new_callable=mock_open, read_data='freeze mem disk')
    def test_get_sleep_state_empty_mem_sleep(self, mock_file):
        mock_file.side_effect = [
            mock_open(read_data='freeze mem disk').return_value,
            mock_open(read_data='').return_value
        ]
        states, current_mem_sleep_state = _get_sleep_state()
        self.assertEqual(states, ['freeze', 'mem', 'disk'])
        self.assertIsNone(current_mem_sleep_state) 

    @patch('dispatcher.device_manager.power_state._is_system_sleeping', return_value=True)
    @patch('dispatcher.device_manager.power_state._get_sleep_state', return_value=(['freeze', 'mem', 'disk'], 's2idle'))
    def test_get_current_power_state_sleeping_with_mem_sleep_state(self, mock_get_sleep_state, mock_is_system_sleeping):
        result = get_current_power_state()
        self.assertEqual(result, 's2idle')

    @patch('dispatcher.device_manager.power_state._is_system_sleeping', return_value=True)
    @patch('dispatcher.device_manager.power_state._get_sleep_state', return_value=(['freeze', 'mem', 'disk'], None))
    def test_get_current_power_state_sleeping_without_mem_sleep_state(self, mock_get_sleep_state, mock_is_system_sleeping):
        result = get_current_power_state()
        self.assertEqual(result, 'sleeping')

    @patch('dispatcher.device_manager.power_state._is_system_sleeping', return_value=False)
    def test_get_current_power_state_on(self, mock_is_system_sleeping):
        result = get_current_power_state()
        self.assertEqual(result, 'on')