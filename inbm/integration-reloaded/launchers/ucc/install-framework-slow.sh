#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../../integration-common/util/tc-messages.sh

set -euxo pipefail

suite_started SETUP
"$DIR"/../vagrant-up.sh

cleanup() {
    suite_finished SETUP
}
trap cleanup 0

test_with_command "INSTALL_FRAMEWORK_UCC" \
    vagrant ssh -c \"sudo /test/ucc/INSTALL_FRAMEWORK_slow.sh\"

"$DIR"/../vagrant-reboot.sh
