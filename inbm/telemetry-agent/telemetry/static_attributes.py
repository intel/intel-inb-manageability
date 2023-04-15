"""
    Handles polling and publishing telemetry data.

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
from . import lsblk
from inbm_common_lib.constants import UNKNOWN
import psutil
import platform
import json
from future import standard_library
standard_library.install_aliases()


def get_os_information() -> str:
    """Get Operating System information

    @return: OS information e.g. "Linux foo.amr.corp.intel.com 4.11.3-202.fc25.x86_64 #1
    SMP Mon Jun 5 16:38:21 UTC 2019"
    """
    return " ".join(platform.uname())


def get_total_physical_memory() -> int:
    """Get total physical memory on the system

    @return: Total physical virtual memory in bytes.
    """
    return psutil.virtual_memory().total


def get_cpu_id() -> str:
    """Get CPU ID

    @return: Brand and model of CPU.
    """
    if platform.system() == "Linux":
        return _get_linux_cpu_id()
    else:
        return platform.machine()


def _get_linux_cpu_id() -> str:
    with open('/proc/cpuinfo') as proc_cpuinfo:
        proc_cpuinfo_data = proc_cpuinfo.read()
    return _get_cpu_id_from_proc_cpuinfo(proc_cpuinfo_data)


def _get_cpu_id_from_proc_cpuinfo(cpuinfo: str) -> str:
    lines = cpuinfo.splitlines()

    model_name_string = "model name\t: "
    model_lines = [x for x in lines if x.startswith(model_name_string)]

    if len(model_lines) > 0:
        return (model_lines[0])[len(model_name_string):]
    else:
        return UNKNOWN


def get_disk_information() -> str:
    """Gets disk information of all disks on the system

    @return: (on Linux) Array of disks attached to system with items containing dictionary fields:
     ROTA - 0 if SSD, 1 if HDD
     NAME - name of device
     SIZE - size of device in bytes
    """
    output = lsblk.get_lsblk_output()
    if output is None:
        return UNKNOWN
    else:
        parsed = lsblk.parse_lsblk(output)
        if parsed is None:
            return UNKNOWN
        return json.dumps(parsed)
