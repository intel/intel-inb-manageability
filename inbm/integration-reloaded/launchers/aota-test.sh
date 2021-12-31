#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

run_vagrant_provision_test() {
    test_with_command "$1" vagrant provision --provision-with \""$1"\"
}

vagrant_provision() {
    vagrant provision --provision-with "$1"
}

suite_started AOTA

cleanup() {
    suite_finished AOTA
}
trap cleanup 0

"$DIR"/vagrant-up.sh
"$DIR"/vagrant-wait-for-up.sh
run_vagrant_provision_test AOTA_LOAD
run_vagrant_provision_test AOTA_IMPORT_MULTIPLE
run_vagrant_provision_test TC15_REMOTE_IMAGE_INSTALL
run_vagrant_provision_test TC16_SUCCESS_PULL_IMAGE
run_vagrant_provision_test TC17_AOTA_DOCKER_STATS
run_vagrant_provision_test AOTA_FAIL_WITH_BAD_MANIFEST.sh

test_started "APPLICATION UPDATE test"
echo .. APPLICATION Update good test running ..
run_vagrant_provision_test AOTA_UPDATE_PREBOOT.sh
"$DIR"/vagrant-reboot.sh
echo .. Checking results of APPLICATION UPDATE good test. ..
if vagrant ssh -c "sudo /test/aota/AOTA_UPDATE_POSTBOOT.sh"; then
    test_pass "AOTA UPDATE good test"
else
    test_fail "AOTA UPDATE good test"
fi

