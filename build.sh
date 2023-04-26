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
cp "$DIR"/inbm/LICENSE "$DIR"/dist/inbm
cp -r "$DIR"/inbm/output/ucc "$DIR"/dist/inbm-ucc

cat >"$DIR"/dist/README.txt <<EOF
Build output files
==================

inbm/install-tc.sh                          Installs inbm for Ubuntu or Debian
inbm/uninstall-tc.sh                        Uninstalls inbm for Ubuntu or Debian
inbm/Intel-Manageability.preview.tar.gz     Holds binary files for inbm
inbm/LICENSE				    INBM license
inbm-ucc/install-tc-ucc.sh                  Installs inbm in UCC mode for Ubuntu or Debian
inbm-ucc/uninstall-tc.sh                    Uninstalls inbm for Ubuntu or Debian
inbm-ucc/Intel-Manageability.ucc.tar.gz     Holds binary files for inbm (UCC agents only)
inbm-ucc/LICENSE                            INBM license
EOF
