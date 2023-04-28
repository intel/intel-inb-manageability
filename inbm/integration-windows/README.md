# Windows Integration Test

This folder includes a Makefile and guidelines for conducting a Windows integration test using Vagrant and VirtualBox.

## Requirements

(taken from https://app.vagrantup.com/peru/boxes/windows-10-enterprise-x64-eval)

"Unfortunately you can not use the Vagrant package provided by your Linux distribution (at least for CentOS / Fedora / Debian). These distributions doesn't support naively Ruby library for WinRM needed by Vagrant for talking to Windows. Luckily WinRM communicator including the Ruby WinRM library is part of official Vagrant package."

See https://developer.hashicorp.com/vagrant/downloads

## Configuration

1. Execute `make install_dependencies` to install necessary dependencies.
2. Build Windows artifacts and transfer the 'windows' output folder from the build to this folder as 'inb-files'. Accomplish this by running `make setup`.
3. Initiate the integration test by running `make test` in this folder.

## Makefile Commands

The `Makefile` includes the following commands:

* `make install_dependencies` - Installs required dependencies for the integration test.
* `make setup` - Deletes the existing `inb-files` folder (if present), builds the Windows output, and transfers it to the `inb-files` folder.
* `make destroy` - Removes the Vagrant environment.
* `make test` - Deactivates the VBoxSymlinkCreate option and configures the Vagrant environment using VirtualBox as the provider.
* `make test` - Reprovision the test system without destroying the VM. Please uninstall Turtle Creek first.

## Further Information

For more details, please consult the `Makefile` in this folder.
