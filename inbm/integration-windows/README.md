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

* `make install_dependencies` - Installs required system dependencies for the integration test. Generally this will only be done once per host system.
* `make setup` - Deletes the existing `inb-files` folder (if present), builds the Windows output, and transfers it to the `inb-files` folder. Any time you want to run or rerun tests this is necessary.
* `make up` - Brings Vagrant VM up from scratch and runs tests.
* `make provision` - Rerun tests without destroying the VM.
* `make destroy` - Removes the Vagrant VM.

## Further Information

For more details, please consult the `Makefile` in this folder.
