#!/bin/bash

set -e # DO NOT REMOVE -- used to fail test if intermediate command fails

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../common/util/bc-messages.sh

suite_started VISION-CONFIG-TEST
"$DIR"/vagrant-up.sh

cleanup() {
    suite_finished VISION-CONFIG-TEST
}
trap cleanup 0

#test_with_command "VISION_CONFIG_VIA_INBC" \
#    vagrant ssh -c \"sudo /test/configuration/VISION_CONFIG_TEST_VIA_INBC.sh\"

test_with_command "VISION_CONFIG" \
    vagrant ssh -c \"sudo /test/configuration/VISION_CONFIG_TEST.sh\"

suite_finished VISION-CONFIG-TEST