set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started NODE-CONFIG-TEST
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished NODE-CONFIG-TEST
}
trap cleanup 0

#test_with_command "NODE_CONFIG_VIA_INBC" \
#    vagrant ssh -c \"sudo /test/configuration/NODE_CONFIG_TEST_VIA_INBC.sh\"

test_with_command "NODE_CONFIG" \
    vagrant ssh -c \"sudo /test/configuration/NODE_CONFIG_TEST.sh\"

suite_finished NODE-CONFIG-TEST