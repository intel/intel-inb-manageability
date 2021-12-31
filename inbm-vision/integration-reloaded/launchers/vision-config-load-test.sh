set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started VISION-CONFIG-LOAD-TEST
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished VISION-CONFIG-LOAD-TEST
}
trap cleanup 0

test_with_command "VISION_CONFIG_LOAD_FAIL" \
    vagrant ssh -c \"sudo /test/configuration/VISION_CONFIG_LOAD_TEST_FAIL.sh\"

test_with_command "VISION_CONFIG_LOAD_PASS" \
    vagrant ssh -c \"sudo /test/configuration/VISION_CONFIG_LOAD_TEST_PASS.sh\"

suite_finished VISION-CONFIG-LOAD-TEST