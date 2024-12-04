# Assuming the get_power_capabilities function is defined in a module named power_capabilities
from telemetry.power_capabilities import PowerCapabilitiesLinux

def test_get_power_capabilities_all_supported(mocker):
    mocker_runner = mocker.patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    mocker_runner.side_effect = [
        ["UNIT FILE      STATE  VENDOR PRESET\nsuspend.target static\nsuspend.target static\n\n1 unit files listed.", None, 0],
        ["UNIT FILE      STATE  VENDOR PRESET\nsuspend.target static\nhibernate.target static\n\n1 unit files listed.", None, 0]
    ]
    
    expected_result = "{\"shutdown\": true, \"reboot\": true, \"suspend\": true, \"hibernate\": true}"
    
    result = PowerCapabilitiesLinux.get_power_capabilities()
    assert result == expected_result
    
def test_get_power_capabilities_suspend_and_hibernate_not_supported(mocker):
    mocker_runner = mocker.patch('inbm_common_lib.shell_runner.PseudoShellRunner.run')
    mocker_runner.side_effect = [
        ["UNIT FILE      STATE  VENDOR PRESET\nsuspend.target static\n\n0 unit files listed.", None, 0],
        ["UNIT FILE      STATE  VENDOR PRESET\nsuspend.target static\n\n0 unit files listed.", None, 0]
    ]
   
    expected_result = "{\"shutdown\": true, \"reboot\": true, \"suspend\": false, \"hibernate\": false}"
    
    result = PowerCapabilitiesLinux.get_power_capabilities()
    assert result == expected_result
