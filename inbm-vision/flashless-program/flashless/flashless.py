""" A tool that run sysfs command to boot flashless device.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import os
import sys
import subprocess
from time import sleep
from typing import List


def boot_device(pcie_id: str, vd_num: str) -> None:
    """Run the sysfs command to boot the device.

    @param pcie_id: PCIe id of device
    @param vd_num: virtual device number, one virtual device associated with one node
    """
    print('Booting device - {0}.'.format(pcie_id))
    with open('/sys/devices/virtual/pcie_vd/pcie_vd-{0}/bind_ep'.format(vd_num), 'w') as vd_file:
        vd_file.write(pcie_id)


def unbind_device(pcie_id: str, vd_num: str) -> None:
    """Unbind the end point of flash logic.

    @param pcie_id: PCIe id of device
    @param vd_num: virtual device number, one virtual device associated with one node
    """
    print('Unbind device - {0}.'.format(pcie_id))
    with open('/sys/devices/virtual/pcie_vd/pcie_vd-{0}/unbind_ep'.format(vd_num), 'w') as vd_file:
        vd_file.write(pcie_id)


def get_all_tbh_device() -> List[str]:
    """Search TBH HDDL devices from PCIe list.

    @param pcie_id: PCIe id of device
    @param vd_num: virtual device number, one virtual device associated with one node
    """
    TBH_FULL = '4fc0'
    TBH_PRIME = '4fc1'
    tbh_full_dev_id = get_pcie_device_id(TBH_FULL)
    tbh_prime_dev_id = get_pcie_device_id(TBH_PRIME)
    print('tbh_full_dev_id: {0}'.format(tbh_full_dev_id))
    print('tbh_prime_dev_id: {0}'.format(tbh_prime_dev_id))
    return tbh_full_dev_id + tbh_prime_dev_id


def get_pcie_device_id(device_type: str) -> List[str]:
    """Search TBH HDDL devices from PCIe list.

    @param device_type: device type. KMB=6240, TBH=4fc0, 4fc1
    @return: string representing PCIe device id, for example, 00:02.0
    """
    get_pcie_command = subprocess.Popen(['lspci'], stdout=subprocess.PIPE, shell=False)
    out, err = get_pcie_command.communicate()
    out_str = out.decode('utf-8', errors='replace').split('\n')
    thb_pcie_list = [pcie_id.split(' ', 1)[0] for pcie_id in out_str if device_type in pcie_id]
    # Filter pcie list to get root device. For example, ['00:1c.0', '00:1c.1'], we only want '00:1c.0'
    thb_pcie_list_filter = [pcie_id for pcie_id in thb_pcie_list if pcie_id.split('.', 1)[1] == "0"]
    return thb_pcie_list_filter


if __name__ == "__main__":
    ori_uid = os.getuid()
    # This program must have root access to execute.
    os.setuid(0)
    if len(sys.argv) > 2:
        if sys.argv[2] == "unbind":
            targets = get_all_tbh_device()
            print('targets are {0}'.format(targets))
            if len(targets) != 0:
                for index, target in enumerate(targets):
                    unbind_device(target, index)
    else:
        targets = get_pcie_device_id(sys.argv[1]) if len(sys.argv) > 1 else get_all_tbh_device()
        print('targets are {0}'.format(targets))
        if len(targets) != 0:
            for index, target in enumerate(targets):
                unbind_device(target, index)
                sleep(2)
                boot_device(target, index)

    # Set uid back to normal before exit
    os.setuid(ori_uid)
    sys.exit(0)
