#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../../integration-common/util/tc-messages.sh
set +e

set -euxo pipefail

test_with_command "CLEAR_TPM" \
    vagrant ssh -c \"sudo /test/general/CLEAR_TPM.sh\"
