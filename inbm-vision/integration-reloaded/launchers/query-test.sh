#!/bin/bash

set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started QUERY
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished QUERY
}
trap cleanup 0

test_with_command "QUERY_TEST_PASS" \
    vagrant ssh -c \"sudo /test/query/QUERY_TEST_PASS.sh\"

test_with_command "QUERY_VISION_VERSION_TEST_PASS" \
    vagrant ssh -c \"sudo /test/query/QUERY_VISION_VERSION_TEST_PASS.sh\"

suite_finished QUERY
