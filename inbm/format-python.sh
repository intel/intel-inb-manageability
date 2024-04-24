#!/bin/bash

set -euxo pipefail

for agent in *-agent ; do autopep8 --max-line-length 99 --exclude '*_pb2*' --in-place -r "$agent" ; done
