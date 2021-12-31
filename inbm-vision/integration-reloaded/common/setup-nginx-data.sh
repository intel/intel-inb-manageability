#!/bin/bash
set -ex
DEST=$1
COMMON=$2

rm -fv ${DEST}/*.tgz

rm -f ${DEST}/U1170000F60X043.tar ${DEST}/U1170000F60X043.bin
cp -v input/U1170000F60X043.tar input/U1170000F60X043.bin ${DEST}

# Create dummy mender file
cat >${DEST}/file.mender <<EOF
dummy file
EOF

# Copy provision.tar
cp -v common/sample_provision.tar ${DEST}
