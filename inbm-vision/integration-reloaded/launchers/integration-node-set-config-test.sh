set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started INTEGRATION-NODE-SET-CONFIG-TEST
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished INTEGRATION-NODE-SET-CONFIG-TEST
}
trap cleanup 0

test_with_command "INTEGRATION_NODE_SET_CONFIG" \
    vagrant ssh -c \"sudo /test/configuration/INTEGRATION_NODE_SET_CONFIG_TEST.sh\"

suite_finished INTEGRATION-NODE-SET-CONFIG-TEST