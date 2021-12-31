#!/bin/bash

set -euxo pipefail

autopep8 --max-line-length 99 --in-place -r inbc
