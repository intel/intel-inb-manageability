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

test_with_command "UCC_GOOD_TELEMETRY_TEST" \
    vagrant ssh -c \"sudo /test/ucc/UCC_GOOD_TELEMETRY_TEST.sh\"

test_with_command "UCC_GOOD_COMMAND_TEST" \
    vagrant ssh -c \"sudo /test/ucc/UCC_GOOD_COMMAND_TEST.sh\"

