#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

suite_started SOTA
"$DIR"/vagrant-up.sh
vagrant ssh -c "dpkg -s ubuntu-release-upgrader-core" || (echo Ubuntu release upgrader missing.  Cannot run SOTA tests. && exit -1)

test_started "update success"
echo .. Update success test running. ..
vagrant ssh -c "sudo /test/sota/SOTA_UPDATE_SUCCESS_preboot.sh" || true
"$DIR"/vagrant-reboot.sh
echo .. Checking results of update success test. ..
if vagrant ssh -c "sudo /test/sota/SOTA_UPDATE_SUCCESS_postboot.sh"; then
	test_pass "update success"
else
	test_fail "update success"
fi

test_started "sota install"
echo .. Sota install test running. ..
if vagrant ssh -c "sudo /test/sota/SOTA_INSTALL.sh"; then
	test_pass "sota install"
else
	test_fail "sota install"
fi

test_started "update success no snapshot"
echo .. Update success test no snapshot running. ..
vagrant ssh -c "sudo /test/sota/SOTA_UPDATE_SUCCESS_NO_SNAPSHOT_preboot.sh" || true
"$DIR"/vagrant-reboot.sh
echo .. Checking results of update success no snapshot test. ..
if vagrant ssh -c "sudo /test/sota/SOTA_UPDATE_SUCCESS_NO_SNAPSHOT_postboot.sh"; then
	test_pass "update success"
else
	test_fail "update success"
fi


test_started "SOTA No-Download success"
echo .. update-No-Download success test running. ..
vagrant ssh -c "sudo /test/sota/SOTA_NO_DOWNLOAD_SUCCESS_preboot.sh" || true
"$DIR"/vagrant-reboot.sh
echo .. Checking results of update success test. ..
if vagrant ssh -c "sudo /test/sota/SOTA_NO_DOWNLOAD_SUCCESS_postboot.sh"; then
        test_pass "sota no-download success"
else
        test_fail "sota no-download success"
fi


"$DIR"/sota-quick-tests/yocto-update-download.sh

suite_finished SOTA
