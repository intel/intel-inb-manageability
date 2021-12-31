#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/common/util/bc-messages.sh

if [[ ! -z "$1" ]] ; then
  ./setup.sh "$1"
else # default
  ./setup.sh
fi

suite_started "Prepare tests"
launchers/vagrant-up.sh
suite_finished "Prepare tests"

launchers/setup-nginx-keys.sh

general() {
  launchers/general-test.sh
}
trap general 0

launchers/install-framework-slow.sh
launchers/query-test.sh
launchers/inbc-file-not-found-test.sh
launchers/provision-node-test.sh
launchers/fota-test.sh
#launchers/sota-test.sh
#launchers/pota-test.sh
# node-config-load-test must be last node config test as it will change the config file permission
launchers/node-config-test.sh
launchers/node-config-load-test.sh
launchers/node-client-config-test.sh
launchers/vision-config-test.sh
# vision-config-load-test must be last vision config test as it will change the config file permission
launchers/vision-config-load-test.sh

# Starting test must be the last test because the test will stop node-agent
launchers/starting-test.sh

# The integration test cases below are primarily to test the TurtleCreek on the node-side - Integration Node
# Manifest -> vision-agent -> node-agent -> node_client
suite_started "Prepare tests"
launchers/vagrant-destroy.sh 
launchers/vagrant-up.sh
suite_finished "Prepare tests"
general() {
  launchers/general-test.sh
}
trap general 0

launchers/install-framework-slow.sh
launchers/integration-node-get-config-test.sh
launchers/integration-node-set-config-test.sh
launchers/integration-node-client-load-config-test.sh
launchers/integration-node-fota-test.sh
launchers/bitcreek-reconnect.sh
launchers/integration-node-fota-test-no-targets.sh
