#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

set -e
set -x

suite_started GENERAL
"$DIR"/vagrant-up.sh
"$DIR"/vagrant-wait-for-up.sh

cleanup() {
    suite_finished GENERAL
}
trap cleanup 0

test_with_command "GENERAL_TEST" \
    vagrant ssh -c \"sudo /test/general/GENERAL_TEST.sh\"
