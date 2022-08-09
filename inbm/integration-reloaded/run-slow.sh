#!/bin/bash
set -e

# $1 is expected to be 18.04 or 20.04 or 22.04 for Ubuntu version
./setup.sh "$1"

. ../integration-common/util/tc-messages.sh

suite_started "Prepare tests"
launchers/vagrant-up.sh
suite_finished "Prepare tests"


general() {
  launchers/general-test.sh
}
trap general 0

launchers/update-system.sh
launchers/install-framework-slow.sh

launchers/setup-servers.sh  # This should happen after any docker uninstalls.
launchers/aota-test.sh
launchers/sota-quick-tests.sh
launchers/fota-test.sh
launchers/config-test.sh
launchers/docker-compose-test.sh
launchers/dbs-test.sh
launchers/reboot-test.sh
launchers/reinstall-framework.sh  # This needs to happen next to last
launchers/safe-mode-test.sh  # This needs to happen last
