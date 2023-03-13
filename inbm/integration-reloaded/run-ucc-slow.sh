#!/bin/bash
set -e

# $1 is expected to be 20.04 or 22.04 for Ubuntu version
./setup.sh "$1"

. ../integration-common/util/tc-messages.sh

suite_started "Prepare tests"
launchers/vagrant-up.sh
suite_finished "Prepare tests"


general() {
  launchers/general-test.sh
}
trap general 0

launchers/ucc/install-framework-slow.sh

launchers/setup-servers.sh  # This should happen after any docker uninstalls.
