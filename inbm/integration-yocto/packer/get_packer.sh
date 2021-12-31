#!/bin/bash
set -euxo pipefail

rm -f *.zip
PACKER=packer_1.2.5_linux_amd64.zip
wget https://releases.hashicorp.com/packer/1.2.5/"$PACKER"
unzip "$PACKER"
rm "$PACKER"
sha256sum -c ./sha256sum-packer
chmod +x packer
