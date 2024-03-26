#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Collect all arguments to pass to the inbm build script (for example, --build-windows=* or --build-check=*)
args="$@"

cd "$DIR"
rm -rf "$DIR"/dist
mkdir -p "$DIR"/dist

# Pass the collected arguments, potentially including --build-windows, to the inbm build script
"$DIR"/inbm/build.sh $args

mkdir -p "$DIR"/dist/inbm
cp "$DIR"/inbm/output/install*.sh "$DIR"/dist/inbm
cp "$DIR"/inbm/output/uninstall*.sh "$DIR"/dist/inbm
cp "$DIR"/inbm/output/Intel*.tar.gz "$DIR"/dist/inbm
cp "$DIR"/inbm/LICENSE "$DIR"/dist/inbm
cp -r "$DIR"/inbm/output/ucc "$DIR"/dist/inbm-ucc

# Copy the inbm-windows.zip only if it exists, as the build might have been skipped
if [ -f "$DIR"/inbm/output/inbm-windows.zip ]; then
    cp "$DIR"/inbm/output/inbm-windows.zip "$DIR"/dist/inbm/inbm-windows.zip
fi

cat >"$DIR"/dist/README.txt <<EOF
Build output files
==================

inbm/install-tc.sh                          Installs inbm for Ubuntu or Debian
inbm/uninstall-tc.sh                        Uninstalls inbm for Ubuntu or Debian
inbm/Intel-Manageability.preview.tar.gz     Holds binary files for inbm
inbm/LICENSE                                INBM license
inbm-ucc/install-tc-ucc.sh                  Installs inbm in UCC mode for Ubuntu or Debian
inbm-ucc/uninstall-tc-ucc.sh                Uninstalls inbm for Ubuntu or Debian
inbm-ucc/Intel-Manageability.ucc.tar.gz     Holds binary files for inbm (UCC agents only)
inbm-ucc/LICENSE                            INBM license
EOF

# Conditionally append information about the Windows zip if it exists
if [ -f "$DIR"/inbm/output/inbm-windows.zip ]; then
cat >>"$DIR"/dist/README.txt <<EOF
inbm/inbm-windows.zip                       INBM for Windows zip file (see "INBM Windows.md" for install guide)

NOTE: INBM for Windows currently only supports UCC mode.
EOF
fi
