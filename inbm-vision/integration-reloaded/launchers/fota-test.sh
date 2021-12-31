#!/bin/bash

set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started FOTA
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished FOTA
}
trap cleanup 0

test_with_command "FOTA_TEST_FAIL_INVALID_NODE" \
    vagrant ssh -c \"sudo /test/fota/FOTA_TEST_FAIL_INVALID_NODE.sh\"

test_with_command "FOTA_TEST_PASS" \
    vagrant ssh -c \"sudo /test/fota/FOTA_TEST_PASS.sh\"

suite_finished FOTA