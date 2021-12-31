#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

test_started "decommission test"
echo .. decommission test running. .
vagrant ssh -c "sudo /test/decommission/DECOMMISSION_TEST.sh" || true
sleep 10
"$DIR"/vagrant-wait-for-up.sh
echo .. Checking results of decommission test. ..
if vagrant ssh -c "sudo /test/decommission/DECOMMISSION_GOOD_TEST_POSTBOOT.sh"; then
        test_pass "decommission test"
else
        test_fail "decommission test"
fi
