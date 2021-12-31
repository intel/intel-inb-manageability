#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

suite_started conifg-tests
cleanup() {
    suite_finished config-tests
}
trap cleanup 0
"$DIR"/vagrant-up.sh

test_with_command "config load success test" \
    vagrant ssh -c \"sudo /test/config/CONFIG_LOAD_SUCCESS.sh\"

test_with_command "config load fail test" \
    vagrant ssh -c \"sudo /test/config/CONFIG_LOAD_FAIL.sh\"

test_with_command "config set pass test" \
    vagrant ssh -c \"sudo /test/config/CONFIG_SET_SUCCESS.sh\"

test_with_command "config set dbs flag lowercase value pass test" \
    vagrant ssh -c \"sudo /test/config/CONFIG_SET_DBS_FLAG_LOWERCASE_VALUE_SUCCESS.sh\"

test_with_command "config get pass test" \
    vagrant ssh -c \"sudo /test/config/CONFIG_GET_SUCCESS.sh\"

test_with_command "config append remove pass test" \
    vagrant ssh -c \"sudo /test/config/CONFIG_APPEND_REMOVE_TEST.sh\"

test_with_command "config get fail test" \
    vagrant ssh -c \"sudo /test/config/CONFIG_GET_FAIL.sh\"

test_with_command "config update fail test" \
    vagrant ssh -c \"sudo /test/config/CONFIG_FAIL_UPDATE.sh\"

test_with_command "config local file load pass test" \
    vagrant ssh -c \"sudo /test/config/CONFIG_LOCAL_FILE_LOAD_TEST.sh\"

suite_finished config-tests

