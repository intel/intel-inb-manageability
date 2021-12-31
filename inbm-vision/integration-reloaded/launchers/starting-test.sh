#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started STARTING
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished STARTING
}
trap cleanup 0

test_with_command "STARTING_TEST" \
    vagrant ssh -c \"sudo /test/starting/STARTING_TEST.sh\"
