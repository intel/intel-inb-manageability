set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started INTEGRATION-NODE-FOTA
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished INTEGRATION-NODE-FOTA
}
trap cleanup 0

test_with_command "INTEGRATION_NODE_FOTA_GOOD_TEST_NO_TARGETS_preboot.sh" \
    vagrant ssh -c \"sudo /test/fota/INTEGRATION_NODE_FOTA_GOOD_TEST_NO_TARGETS_preboot.sh\"

"$DIR"/vagrant-reboot.sh

test_with_command "INTEGRATION_NODE_FOTA_GOOD_TEST_NO_TARGETS_postboot.sh" \
    vagrant ssh -c \"sudo /test/fota/INTEGRATION_NODE_FOTA_GOOD_TEST_NO_TARGETS_postboot.sh\"

suite_finished INTEGRATION-NODE-FOTA