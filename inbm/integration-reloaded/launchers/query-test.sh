#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

suite_started query-test
cleanup() {
    suite_finished query-test
}
trap cleanup 0
"$DIR"/vagrant-up.sh

test_with_command "query all success test" \
    vagrant ssh -c \"sudo /test/query/QUERY_ALL_SUCCESS.sh\"

test_with_command "query fail test" \
    vagrant ssh -c \"sudo /test/query/QUERY_FAIL.sh\"

suite_finished query-test

