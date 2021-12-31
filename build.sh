#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$DIR"
rm -rf "$DIR"/dist
mkdir -p "$DIR"/dist

"$DIR"/inbm/build.sh
mkdir -p "$DIR"/dist/inbm
cp "$DIR"/inbm/output/install*.sh "$DIR"/dist/inbm
cp "$DIR"/inbm/output/uninstall*.sh "$DIR"/dist/inbm
cp "$DIR"/inbm/output/Intel*.tar.gz "$DIR"/dist/inbm

"$DIR"/inbm-vision/build.sh
mkdir -p "$DIR"/dist/inbm-vision
cp "$DIR"/inbm-vision/output/*.deb "$DIR"/dist/inbm-vision
cp "$DIR"/inbm-vision/output/*install*.sh "$DIR"/dist/inbm-vision

cat >dist/README.txt <<EOF
Build output files
==================

inbm/install-inb.sh                         Installs both inbm and inbm-vision for Ubuntu or Debian
inbm/install-tc.sh                          Installs inbm for Ubuntu or Debian
inbm/uninstall-inb.sh                       Uninstalls both inbm and inbm-vision for Ubuntu or Debian
inbm/uninstall-tc.sh                        Uninstalls inbm for Ubuntu or Debian
inbm/Intel-Manageability.preview.tar.gz     Holds binary files for inbm

inbm-vision/install-bc.sh                   Installs vision or node agent from inbm-vision
inbm-vision/uninstall-bc.sh                 Uninstalls vision or node agent from inbm-vision
inbm-vision/*.deb                           Hold binary files for inbm-vision
EOF
