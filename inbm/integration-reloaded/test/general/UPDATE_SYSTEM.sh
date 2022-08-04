#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

set -euxo pipefail

# disable slow kernel upgrades
apt-mark hold linux-generic linux-image-generic linux-headers-generic


# Update the system here to standardize/simplify further test results.
apt-get update
apt-get -y upgrade || ( apt-get -y -f install && apt-get -y upgrade )
apt-get clean
