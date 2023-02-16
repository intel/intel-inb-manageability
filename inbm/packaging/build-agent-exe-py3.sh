#!/bin/bash

set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

AGENT=$1
FORMAT=$2
PLATFORM=$3 # 'EVAL' or 'KMB': if 'KMB' we expect to see a binary in ./exe
TYPE=$4 # 'agent' for agent or 'program' for program


AGENTDIR="$AGENT-$TYPE"
if [ $AGENT == "inbm-dispatcher" ] ; then AGENTDIR="dispatcher-$TYPE" ; fi
if [ $AGENT == "inbm-diagnostic" ] ; then AGENTDIR="diagnostic-$TYPE" ; fi
if [ $AGENT == "inbm-telemetry" ] ; then AGENTDIR="telemetry-$TYPE" ; fi
if [ $AGENT == "inbm-configuration" ] ; then AGENTDIR="configuration-$TYPE" ; fi
if [ $AGENT == "inbm-cloudadapter" ] ; then AGENTDIR="cloudadapter-$TYPE" ; fi

rm -rf dist build fpm-files
mkdir -p dist
cp -r fpm-template fpm-files
mkdir -p fpm-files/usr/share/"$AGENTDIR"/
mkdir -p fpm-files/usr/bin/

pwd
#Build and copy executable into DEB staging area
if [[ "$PLATFORM" = "EVAL" ]] || [[ "$PLATFORM" = "EHL" ]] ; then
    "$DIR"/run-pyinstaller-py3.sh "$AGENT-$TYPE" "$AGENT"
    cp -r ../"$AGENTDIR"/dist/*"$AGENT" fpm-files/usr/bin/
    chmod +x fpm-files/usr/bin/*"$AGENT"
elif [ ${PLATFORM} = "KMB" ]; then
    cp -r exe/*${AGENT} fpm-files/usr/bin/
    chmod +x fpm-files/usr/bin/*"$AGENT"
else
    echo Unrecognized platform: "${PLATFORM}"
    exit 1
fi

# Adhoc KMB packaging changes should go here!
if [ "${PLATFORM}" = "KMB" ] && [ "${AGENT}" = "configuration" ]; then
    cp ../packaging/yocto/kmb/intel_manageability.conf fpm-files/etc/intel_manageability.conf
    cp ../packaging/yocto/kmb/firmware_tool_info.conf fpm-files/etc/firmware_tool_info.conf
fi

# Adhoc EHL packaging changes should go here!
if [ "${PLATFORM}" = "EHL" ] && [ "${AGENT}" = "inbm-configuration" ]; then
    cp ../packaging/yocto/ehl/intel_manageability.conf fpm-files/etc/intel_manageability.conf
    cp ../packaging/yocto/ehl/firmware_tool_info.conf fpm-files/etc/firmware_tool_info.conf
fi

if [ "${PLATFORM}" = "EHL" ] && [ "${AGENT}" = "inbm-dispatcher" ]; then
    cp ../packaging/yocto/common/usr.bin.inbm-dispatcher fpm-files/etc/apparmor.d/usr.bin.inbm-dispatcher
fi

if [ "${PLATFORM}" = "KMB" ] && [ "${AGENT}" = "inbm-dispatcher" ]; then
    cp ../packaging/yocto/common/usr.bin.inbm-dispatcher fpm-files/etc/apparmor.d/usr.bin.inbm-dispatcher
fi

if [ "${PLATFORM}" = "KMB" ] && [ "${AGENT}" = "inbm-configuration" ]; then
    cp ../packaging/yocto/common/usr.bin.inbm-configuration fpm-files/etc/apparmor.d/usr.bin.inbm-configuration
fi

if [ "${PLATFORM}" = "EHL" ] && [ "${AGENT}" = "inbm-telemetry" ]; then
    cp ../packaging/yocto/common/usr.bin.inbm-telemetry fpm-files/etc/apparmor.d/usr.bin.inbm-telemetry
fi

if [ "${PLATFORM}" = "KMB" ] && [ "${AGENT}" = "inbm-telemetry" ]; then
    cp ../packaging/yocto/common/usr.bin.inbm-telemetry fpm-files/etc/apparmor.d/usr.bin.inbm-telemetry
fi

if [ "${PLATFORM}" = "EHL" ] && [ "${AGENT}" = "inbm-cloudadapter" ]; then
    cp ../packaging/yocto/common/usr.bin.inbm-cloudadapter fpm-files/etc/apparmor.d/usr.bin.inbm-cloudadapter
fi

if [ "${PLATFORM}" = "KMB" ] && [ "${AGENT}" = "inbm-cloudadapter" ]; then
    cp ../packaging/yocto/common/usr.bin.inbm-cloudadapter fpm-files/etc/apparmor.d/usr.bin.inbm-cloudadapter
fi

if [ "${PLATFORM}" = "EHL" ] && [ "${AGENT}" = "inbm-diagnostic" ]; then
    cp ../packaging/yocto/common/usr.bin.inbm-diagnostic fpm-files/etc/apparmor.d/usr.bin.inbm-diagnostic
fi

if [ "${PLATFORM}" = "KMB" ] && [ "${AGENT}" = "inbm-diagnostic" ]; then
    cp ../packaging/yocto/common/usr.bin.inbm-diagnostic fpm-files/etc/apparmor.d/usr.bin.inbm-diagnostic
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
fpm -t "$FORMAT"\
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
