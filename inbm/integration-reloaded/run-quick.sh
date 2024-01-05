#!/bin/bash
set -e

./setup.sh

. ../integration-common/util/tc-messages.sh

suite_started "Prepare tests"
launchers/vagrant-up.sh
suite_finished "Prepare tests"

launchers/setup-servers.sh

general() {
  launchers/general-test.sh
}
trap general 0

launchers/install-framework-quick.sh
launchers/update-system.sh
launchers/source-test.sh
launchers/aota-test.sh
launchers/sota-quick-tests.sh
launchers/fota-test.sh
launchers/pota-test.sh
launchers/config-test.sh
launchers/docker-compose-test.sh
launchers/dbs-test.sh
launchers/reboot-test.sh
launchers/decommission-test.sh
