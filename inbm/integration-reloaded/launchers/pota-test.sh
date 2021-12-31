#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

suite_started POTA
"$DIR"/vagrant-up.sh
"$DIR"/vagrant-wait-for-up.sh

test_with_command "POTA REMOTE TAG test" vagrant ssh -c \"sudo /test/pota/POTA_TEST_SUCCESS_WITH_REMOTE_TAG.sh\"
"$DIR"/vagrant-reboot.sh
echo .. Checking results of POTA REMOTE tag test. ..
if vagrant ssh -c "sudo /test/fota/FOTA_GOOD_AMI_TEST_postboot.sh"; then
    test_pass "FOTA successful under POTA REMOTE tag test"
else
    test_fail "FOTA failed under POTA REMOTE tag test"
fi
if vagrant ssh -c "sudo /test/sota/SOTA_YOCTO_UPDATE_DOWNLOAD_postboot.sh"; then
        test_pass "SOTA successful under POTA REMOTE tag test"
else
        test_fail "SOTA failed under POTA REMOTE tag test"
fi

test_with_command "POTA LOCAL TAG test" vagrant ssh -c \"sudo /test/pota/POTA_TEST_SUCCESS_WITH_LOCAL_TAG.sh\"
"$DIR"/vagrant-reboot.sh
echo .. Checking results of POTA LOCAL tag test. ..
if vagrant ssh -c "sudo /test/fota/FOTA_GOOD_AMI_TEST_postboot.sh"; then
    test_pass "FOTA successful under POTA REMOTE tag test"
else
    test_fail "FOTA failed under POTA REMOTE tag test"
fi
if vagrant ssh -c "sudo /test/sota/SOTA_YOCTO_UPDATE_DOWNLOAD_postboot.sh"; then
        test_pass "SOTA successful under POTA REMOTE tag test"
else
        test_fail "SOTA failed under POTA REMOTE tag test"
fi

suite_finished POTA
