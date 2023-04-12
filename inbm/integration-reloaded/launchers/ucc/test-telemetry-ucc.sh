#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../../integration-common/util/tc-messages.sh

set -euxo pipefail

suite_started TEST TELEMETRY UCC
"$DIR"/../vagrant-up.sh

cleanup() {
    suite_finished TEST TELEMETRY UCC
}
trap cleanup 0

test_with_command "TEST_TELEMETRY_UCC" \
    vagrant ssh -c \"sudo /test/ucc/TEST_TELEMETRY_ucc.sh\"

# "$DIR"/../vagrant-reboot.sh
