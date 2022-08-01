#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh


test_started "reboot test"
echo .. reboot test running. .
vagrant ssh -c "sudo /test/reboot/REBOOT_GOOD_TEST.sh" || true
sleep 10
"$DIR"/vagrant-wait-for-up.sh
echo .. Checking results of reboot test. ..
if vagrant ssh -c "sudo /test/reboot/REBOOT_GOOD_TEST_POSTBOOT.sh"; then
        test_pass "reboot test"
else
        test_fail "reboot test"
fi

sleep 10
"$DIR"/vagrant-wait-for-up.sh
echo .. cslm reboot test pass running. .
vagrant ssh -c "sudo /test/reboot/REBOOT_CSLM_TEST_PASS.sh" || true
sleep 10
"$DIR"/vagrant-wait-for-up.sh
echo .. Checking results of reboot test pass. ..
if vagrant ssh -c "sudo /test/reboot/REBOOT_CSLM_TEST_POSTBOOT.sh"; then
        test_pass "cslm reboot test"
else
        test_fail "cslm reboot test"
fi

