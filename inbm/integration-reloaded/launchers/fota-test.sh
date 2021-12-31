#!/bin/bash
#./vagrant-reboot.sh

#set -e # NOT required since rebooting vagrant below would cause a 255 failure which fails the entire test case.

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

suite_started FOTA
"$DIR"/vagrant-up.sh
"$DIR"/vagrant-wait-for-up.sh

test_with_command "FOTA bad nonmatching" vagrant ssh -c \"sudo /test/fota/FOTA_BAD_NONMATCHING.sh\"
test_with_command "FOTA bad releasedatelower" vagrant ssh -c \"sudo /test/fota/FOTA_BAD_RELEASEDATELOWER.sh\"

test_started "FOTA good test"
echo .. FOTA good test running ..
vagrant ssh -c "sudo /test/fota/FOTA_GOOD_TEST_preboot.sh"
"$DIR"/vagrant-reboot.sh
echo .. Checking results of FOTA good test. ..
if vagrant ssh -c "sudo /test/fota/FOTA_GOOD_TEST_postboot.sh"; then
    test_pass "FOTA good test"
else
    test_fail "FOTA good test"
fi


test_started "FOTA local test"
echo .. FOTA local test running ..
vagrant ssh -c "sudo /test/fota/FOTA_GOOD_LOCAL_TEST_preboot.sh"
"$DIR"/vagrant-reboot.sh
echo .. Checking results of FOTA local test. ..
if vagrant ssh -c "sudo /test/fota/FOTA_GOOD_LOCAL_TEST_postboot.sh"; then
    test_pass "FOTA local test"
else
    test_fail "FOTA local test"
fi

test_started "FOTA good AMI test"
echo .. FOTA good AMI test running ..
vagrant ssh -c "sudo /test/fota/FOTA_GOOD_AMI_TEST_preboot.sh"
"$DIR"/vagrant-reboot.sh
echo .. Checking results of FOTA good AMI test. ..
if vagrant ssh -c "sudo /test/fota/FOTA_GOOD_AMI_TEST_postboot.sh"; then
    test_pass "FOTA good AMI test"
else
    test_fail "FOTA good AMI test"
fi

test_started "FOTA good test no tar"
echo .. FOTA good test no tar running ..
vagrant ssh -c "sudo /test/fota/FOTA_GOOD_TEST_NO_TAR_preboot.sh"
"$DIR"/vagrant-reboot.sh
echo .. Checking results of FOTA good test no tar. ..
if vagrant ssh -c "sudo /test/fota/FOTA_GOOD_TEST_NO_TAR_postboot.sh"; then
    test_pass "FOTA good test no tar"
else
    test_fail "FOTA good test no tar"
fi

test_started "FOTA good INBC platform info match "
echo .. FOTA good INBC platform info match test running ..
vagrant ssh -c "sudo /test/fota/FOTA_GOOD_INBC_PLATFORM_INFO_MATCH_preboot.sh"
"$DIR"/vagrant-reboot.sh
echo .. Checking results of FOTA good AMI test. ..
if vagrant ssh -c "sudo /test/fota/FOTA_GOOD_INBC_PLATFORM_INFO_MATCH_postboot.sh"; then
    test_pass "FOTA good INBC platform info match"
else
    test_fail "FOTA good INBC platform info match"
fi

# timeout 1m vagrant provision --provision-with fota_good_ami_test_preboot || true
# vagrant provision --provision-with fota_good_ami_test_postboot

# timeout 1m vagrant provision --provision-with fota_good_test_no_tar_preboot || true
# vagrant provision --provision-with fota_good_ami_test_no_tar_postboot

suite_finished FOTA
