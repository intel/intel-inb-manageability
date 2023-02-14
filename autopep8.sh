#!/bin/bash

set -euxo pipefail

for dir in inbc-program inbm inbm-lib ; do
	( cd "$dir"
	 ./autopep8.sh
	)
done
