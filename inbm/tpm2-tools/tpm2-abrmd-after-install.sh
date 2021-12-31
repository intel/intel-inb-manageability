#!/bin/bash
set -euxo pipefail

ldconfig
udevadm control --reload-rules
udevadm trigger
systemctl enable tpm2-abrmd