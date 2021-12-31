#!/bin/bash

set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

set -ex pipefail

suite_started GENERAL
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished GENERAL
}
trap cleanup 0

test_with_command "GENERAL_TEST" \
    vagrant ssh -c \"sudo /test/general/GENERAL_TEST.sh\"

