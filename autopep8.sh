#!/bin/bash

set -euxo pipefail

for dir in inbc-program inbm inbm-vision inbm-lib ; do
	( cd "$dir"
	 ./autopep8.sh
	)
done
