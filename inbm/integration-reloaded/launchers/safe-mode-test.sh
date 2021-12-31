#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh


suite_started "safe mode"
test_started "safe mode test"
echo .. safe mode test running ..
vagrant ssh -c "sudo /test/safe-mode/SAFE_MODE.sh"
suite_finished "safe mode"
