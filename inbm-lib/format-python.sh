#!/bin/bash

set -euxo pipefail

for i in inbm_lib ; do autopep8 --max-line-length 99 --in-place -r "$i" ; done
