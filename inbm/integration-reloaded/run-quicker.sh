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

launchers/install-framework-quicker.sh
launchers/aota-test.sh
launchers/dbs-confirm-off.sh
