import unittest
from unittest.mock import patch, MagicMock
import dbus

# Assuming the get_power_capabilities function is defined in a module named power_capabilities
from telemetry.power_capabilities import get_power_capabilities

class TestGetPowerCapabilities(unittest.TestCase):

    @patch('dbus.SystemBus')
    def test_get_power_capabilities_all_supported(self, mock_system_bus):
        # Mock the D-Bus interface methods to return 'yes' for all power states
        mock_interface = MagicMock()
        mock_interface.CanPowerOff.return_value = 'yes'
        mock_interface.CanReboot.return_value = 'yes'
        mock_interface.CanSuspend.return_value = 'yes'
        mock_interface.CanHibernate.return_value = 'yes'

        # Mock the D-Bus proxy object and interface
        mock_proxy = MagicMock()
        mock_system_bus.return_value.get_object.return_value = mock_proxy
        mock_proxy.CanPowerOff = mock_interface.CanPowerOff
        mock_proxy.CanReboot = mock_interface.CanReboot
        mock_proxy.CanSuspend = mock_interface.CanSuspend
        mock_proxy.CanHibernate = mock_interface.CanHibernate

        expected_result = {
            "shutdown": True,
            "reboot": True,
            "suspend": True,
            "hibernate": True
        }

        result = get_power_capabilities()
        self.assertEqual(result, expected_result)

    @patch('dbus.SystemBus')
    def test_get_power_capabilities_none_supported(self, mock_system_bus):
        # Mock the D-Bus interface methods to return 'no' for all power states
        mock_interface = MagicMock()
        mock_interface.CanPowerOff.return_value = 'no'
        mock_interface.CanReboot.return_value = 'no'
        mock_interface.CanSuspend.return_value = 'no'
        mock_interface.CanHibernate.return_value = 'no'

        # Mock the D-Bus proxy object and interface
        mock_proxy = MagicMock()
        mock_system_bus.return_value.get_object.return_value = mock_proxy
        mock_proxy.get_dbus_method.return_value = mock_interface

        expected_result = {
            "shutdown": False,
            "reboot": False,
            "suspend": False,
            "hibernate": False
        }

        result = get_power_capabilities()
        self.assertEqual(result, expected_result)

    @patch('dbus.SystemBus')
    def test_get_power_capabilities_dbus_exception(self, mock_system_bus):
        # Mock the D-Bus interface to raise a DBusException
        mock_system_bus.return_value.get_object.side_effect = dbus.DBusException

        expected_result = {
            "shutdown": False,
            "reboot": False,
            "suspend": False,
            "hibernate": False
        }

        with self.assertLogs('power_capabilities', level='ERROR') as log:
            result = get_power_capabilities()
            self.assertEqual(result, expected_result)
            self.assertIn("DBus error gathering power capabilities", log.output[0])

if __name__ == '__main__':
    unittest.main()
