#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

run_vagrant_provision_test() {
    test_with_command "$1" vagrant provision --provision-with \""$1"\"
}

vagrant_provision() {
    vagrant provision --provision-with "$1"
}

suite_started SOURCE

cleanup() {
    suite_finished SOURCE
}
trap cleanup 0

"$DIR"/vagrant-up.sh
"$DIR"/vagrant-wait-for-up.sh

test_started "SOURCE test"
vagrant ssh -c "sudo /test/source/SOURCE.sh"
