#!/bin/bash

set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started INBC_FILE_NOT_FOUND
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished INBC_FILE_NOT_FOUND
}
trap cleanup 0

test_with_command "INBC_FILE_NOT_FOUND_PASS" \
    vagrant ssh -c \"sudo /test/fota/FOTA_INBC_FILE_NOT_FOUND.sh\"

suite_finished INBC_FILE_NOT_FOUND
