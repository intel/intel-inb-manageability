#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../../integration-common/util/tc-messages.sh


test_started "yocto update download"
echo .. Yocto update download test running. ..
vagrant ssh -c "sudo /test/sota/SOTA_YOCTO_UPDATE_DOWNLOAD_preboot.sh" || true
"$DIR"/../vagrant-reboot.sh
echo .. Checking results of yocto update download test. ..
if vagrant ssh -c "sudo /test/sota/SOTA_YOCTO_UPDATE_DOWNLOAD_postboot.sh"; then
        test_pass "yocto update download"
else
        test_fail "yocto update download"
fi
