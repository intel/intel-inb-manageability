#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

run_vagrant_provision_test() {
    test_with_command "$1" vagrant provision --provision-with \""$1"\"
}

vagrant_provision() {
    vagrant provision --provision-with "$1"
}

suite_started DBS

cleanup() {
    suite_finished DBS
}
trap cleanup 0

"$DIR"/vagrant-up.sh

# TODO: fix for new DBS
# run_vagrant_provision_test dbs_fail

# TODO: rewrite and re-enable
# run_vagrant_provision_test dbs_check_remediation
