"""
    Central telemetry service for the manageability framework 

    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
#import subprocess
import json
from inbm_common_lib.shell_runner import PseudoShellRunner

class PowerCapabilitiesLinux:
    """Class to get power capabilities on Linux"""
    
    @staticmethod
    def _check_command(command: list[str]) -> bool:
        combined_cmd = " ".join(command)
        out, _, code = PseudoShellRunner().run(combined_cmd)
        if code != 0:
            return False
        return True if "1 unit files listed." in out else False

    @staticmethod
    def get_power_capabilities() -> str:
        """Return a dictionary of power capabilities."""
        power_states = {
            "shutdown": True,  # Always supported
            "reboot": True,    # Always supported
            "suspend": PowerCapabilitiesLinux._check_command(["systemctl", "list-unit-files", "suspend.target"]),
            "hibernate": PowerCapabilitiesLinux._check_command(["systemctl", "list-unit-files", "hibernate.target"])
        }
        
        return json.dumps(power_states)    
