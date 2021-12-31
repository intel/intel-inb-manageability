set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started NODE-CLIENT-CONFIG-TEST
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished NODE-CLIENT-CONFIG-TEST
}
trap cleanup 0

test_with_command "NODE_CLIENT_CONFIG" \
    vagrant ssh -c \"sudo /test/configuration/NODE_CLIENT_CONFIG_TEST.sh\"

suite_finished NODE-CLIENT-CONFIG-TEST