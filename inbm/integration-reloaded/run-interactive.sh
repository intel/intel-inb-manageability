#!/bin/bash
set -e

rm -f input
rm -rf ../output
../build.sh
ln -sf ../output ./input

# $1 is expected to be 20.04 or 22.04 for Ubuntu version
./setup.sh "$1"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"


launchers/vagrant-up.sh
launchers/setup-servers.sh
launchers/install-framework-quicker.sh
