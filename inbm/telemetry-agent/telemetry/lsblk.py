"""
    Retrieves attached disk information.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from typing import List, Optional
from inbm_common_lib.shell_runner import PseudoShellRunner
import platform
from future import standard_library
standard_library.install_aliases()


def parse_lsblk(lsblk_output) -> Optional[List]:
    """Parse output of lsblk command with name, size, and ssd status of attached disks.
    @param lsblk_output: text output of lsblk command

    @return: python data structure: array of dictionaries with keys NAME, SIZE, ROTA
    """
    lines = lsblk_output.splitlines()
    result = []

    if len(lines) < 1:
        return None

    if lines[0].split() != ["NAME", "SIZE", "ROTA"]:
        return None

    for line in lines[1:]:
        fields = line.split()
        result.append({"NAME": fields[0], "SIZE": fields[1],
                       "SSD": "True" if fields[2] == "0" else "False"})

    return result


def get_lsblk_output() -> Optional[str]:
    """Run an lsblk command to get name, size, and ssd status of attached disks.

    @return: Command output or None if anything printed on stderr
    """
    if platform.system() == 'Linux':
        (out, err, code) = PseudoShellRunner.run("lsblk -b -d -o name,size,rota")
        return out if err == "" and code == 0 else None
    return None
