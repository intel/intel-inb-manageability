#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
mypy --config-file "$DIR"/mypy.ini --check-untyped-defs "$@"
