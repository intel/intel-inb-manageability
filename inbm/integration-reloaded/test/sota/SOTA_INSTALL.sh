#!/bin/bash

set -euxo # DO NOT REMOVE -- used to fail test if intermediate command fails

source /scripts/test_util.sh

mkdir -p /var/log/sota_test

echo "Triggering SOTA test: INSTALL"
echo "<START> SOTA INSTALL" | systemd-cat


# Function to check if a package is installed
is_package_installed() {
    dpkg -s "$1" &> /dev/null
}

for package in hello cowsay ; do
  if is_package_installed $package; then
      echo "Error: The package '$package' is already installed."
      exit 1
  fi
done

inbc sota --package-list hello,cowsay --reboot no --mode download-only
inbc sota --package-list hello,cowsay --reboot no --mode no-download

for package in hello cowsay ; do
  if ! is_package_installed $package; then
      echo "Error: The installation of the package '$package' failed."
      echo "<FAILED> SOTA INSTALL TEST"
      exit 1
  fi
done