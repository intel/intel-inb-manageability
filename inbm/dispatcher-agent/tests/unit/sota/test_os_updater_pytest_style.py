import pytest
from unittest.mock import patch
from dispatcher.sota.os_updater import DebianBasedUpdater, mender_install_argument
from inbm_lib.constants import DOCKER_CHROOT_PREFIX, CHROOT_PREFIX

# Test when '-install' argument is present in the help output


def test_mender_install_argument_present(mocker) -> None:
    mocked_run = mocker.patch('dispatcher.sota.os_updater.PseudoShellRunner.run')
    mocked_run.return_value = ("Usage of the command with -install option", "", 0)

    assert mender_install_argument(
    ) == "-install", "Function should return '-install' when it is present in the help output"

# Test when 'install' should be the argument (the '-install' argument is absent)


def test_mender_install_argument_absent(mocker) -> None:
    mocked_run = mocker.patch('dispatcher.sota.os_updater.PseudoShellRunner.run')
    mocked_run.return_value = ("Usage of the command with only install option", "", 0)

    assert mender_install_argument(
    ) == "install", "Function should return 'install' when '-install' is not present in the help output"


@pytest.fixture
def debian_updater():
    package_list = ['package1', 'package2']
    return DebianBasedUpdater(package_list)


@pytest.mark.parametrize("is_docker_env, package_list, expected_commands", [
    (False, ['package1', 'package2'], ["apt-get update",
                                       "dpkg-query -f '${binary:Package}\\n' -W",
                                       "dpkg --configure -a --force-confdef --force-confold",
                                       "apt-get -yq -f -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install",
                                       "apt-get -yq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install package1 package2"]),
    (True, ['package1', 'package2'], [f"{CHROOT_PREFIX}/usr/bin/apt-get update",
                                      f"{CHROOT_PREFIX}/usr/bin/apt-get -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' -f -yq --download-only install",
                                      f"{DOCKER_CHROOT_PREFIX}/usr/bin/apt-get -yq -f -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'  install",
                                      f"{DOCKER_CHROOT_PREFIX}/usr/bin/dpkg-query -f '${{binary:Package}}\\n' -W",
                                      f"{CHROOT_PREFIX}/usr/bin/dpkg --configure -a --force-confdef --force-confold",
                                      f"{DOCKER_CHROOT_PREFIX}/usr/bin/apt-get -yq --download-only -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install package1 package2",
                                      f"{DOCKER_CHROOT_PREFIX}/usr/bin/apt-get -yq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' --with-new-pkgs upgrade"])
])
def test_update_remote_source(debian_updater, is_docker_env, package_list, expected_commands, mocker) -> None:
    debian_updater._package_list = package_list

    mocker.patch.dict('os.environ', {
        'DEBIAN_FRONTEND': 'noninteractive',
        'container': 'docker' if is_docker_env else ''
    })

    cmds = debian_updater.update_remote_source(None, None, None)

    assert [cmd.text for cmd in cmds] == expected_commands
