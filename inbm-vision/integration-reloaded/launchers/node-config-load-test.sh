set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started NODE-CONFIG-LOAD-TEST
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished NODE-CONFIG-LOAD-TEST
}
trap cleanup 0

# Test no longer viable after changes to cancel timer.
#test_with_command "NODE_CONFIG_LOAD" \
#    vagrant ssh -c \"sudo /test/configuration/NODE_CONFIG_LOAD_TEST_FAIL_OTA_IN_PROGRESS.sh\"

test_with_command "NODE_CONFIG_LOAD" \
    vagrant ssh -c \"sudo /test/configuration/NODE_CONFIG_LOAD_TEST.sh\"

suite_finished NODE-CONFIG-LOAD-TEST