#!/bin/bash

set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

AGENT=$1
FORMAT=$2
PLATFORM=$3 # 'EVAL' or 'KMB': if 'KMB' we expect to see a binary in ./exe
TYPE=$4 # 'agent' for agent or 'program' for program

AGENTDIR="$AGENT-$TYPE"
if [ $AGENT == "inbm-vision" ] ; then AGENTDIR="vision-$TYPE" ; fi
if [ $AGENT == "inbm-node" ] ; then AGENTDIR="node-$TYPE" ; fi

rm -rf dist build fpm-files
mkdir -p dist
cp -r fpm-template fpm-files
mkdir -p fpm-files/usr/share/"$AGENTDIR"-"$TYPE"/
mkdir -p fpm-files/usr/bin/

pwd
#Build and copy executable into DEB staging area
if [[ "$PLATFORM" = "EVAL" ]] || [[ "$PLATFORM" = "EHL" ]] ; then
    "$DIR"/run-pyinstaller-py3.sh "$AGENT-$TYPE" "$AGENT"
    echo copying pyinstaller binary
    cp -r ../"$AGENTDIR"/dist/"$AGENT" fpm-files/usr/bin/
    chmod +x fpm-files/usr/bin/"$AGENT"
    # Vision doesn't like having a dash in its binary filename.
    if [ $AGENT == "inbm-vision" ] ; then mv fpm-files/usr/bin/inbm-vision fpm-files/usr/bin/vision ; fi
elif [ ${PLATFORM} = "KMB" ]; then
    echo copying pyinstaller binary
    cp -r exe/${AGENT} fpm-files/usr/bin/
    chmod +x fpm-files/usr/bin/"$AGENT"
    # Vision doesn't like having a dash in its binary filename.
    if [ $AGENT == "inbm-vision" ] ; then mv fpm-files/usr/bin/inbm-vision fpm-files/usr/bin/vision ; fi
else
    echo Unrecognized platform: "${PLATFORM}"
    exit 1
fi

ITERATION=`cat iteration.txt`
NAME="$AGENT"-"$TYPE"
VERSION="$(cat ../version.txt)"

if [ -z "${BUILD_NUMBER+x}" ]; then
    ITERATION=${ITERATION}
else
    ITERATION=${BUILD_NUMBER}
fi

PACKAGE_NAME="$NAME-$VERSION-$ITERATION.$PLATFORM.$2"
fpm -t $2\
    --after-install scripts/after-install.sh\
    --before-install scripts/before-install.sh\
    --before-remove scripts/before-remove.sh\
    --iteration ${ITERATION}\
    -s dir\
    -C fpm-files\
    -p "$PACKAGE_NAME"\
    -f\
    -n ${NAME}\
    -v ${VERSION}\
    --no-auto-depends\
    --depends lxc\
    -a all\
    -m none\
    .

mkdir -p dist/
mv -f "$PACKAGE_NAME" dist/
