#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../../integration-common/util/tc-messages.sh

set -euxo pipefail

suite_started UCC
"$DIR"/../vagrant-up.sh

cleanup() {
    suite_finished UCC
}
trap cleanup 0

test_with_command "UCC_FLOW_TEST" \
    vagrant ssh -c \"sudo /test/ucc/UCC_FLOW_TEST.py\"
