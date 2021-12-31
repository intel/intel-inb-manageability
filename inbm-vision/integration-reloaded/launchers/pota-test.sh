#!/bin/bash

set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started POTA
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished POTA
}
trap cleanup 0

# Need a Yocto vagrant image in order to test SOTA on a node.
test_with_command "POTA_TEST_PASS" \
    vagrant ssh -c \"sudo /test/pota/POTA_TEST_PASS.sh\"

suite_finished POTA