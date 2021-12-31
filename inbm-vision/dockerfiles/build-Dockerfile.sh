#!/bin/bash
set -euxo pipefail

if [ $# -eq 0 ]
  then
    echo "No arguments supplied. Expected: main for dockerfiles/Dockerfile-main.m4, check for dockerfiles/Dockerfile-check.m4, etc"
    exit 1
fi

DOCKER_CONTENT_TRUST=0
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

NAME=inb-"${1,,}"

TMPFILE=$(mktemp -p . tmp.Dockerfile-"$1".XXXX)
m4 -I "$DIR" "$DIR"/Dockerfile-"$1".m4 >"$TMPFILE"

VERSION=$(cat $DIR/../version.txt)
if ! git rev-parse --short HEAD >&/dev/null ; then
    COMMIT="none"
else
    COMMIT=$(git rev-parse --short HEAD)
fi
echo $VERSION
echo $COMMIT

docker build \
    --build-arg HTTP_PROXY=${HTTP_PROXY:-} \
    --build-arg http_proxy=${http_proxy:-} \
    --build-arg HTTPS_PROXY=${HTTPS_PROXY:-} \
    --build-arg https_proxy=${https_proxy:-} \
    --build-arg NO_PROXY=${NO_PROXY:-} \
    --build-arg no_proxy=${no_proxy:-} \
    --build-arg VERSION="$VERSION" \
    --build-arg COMMIT="$COMMIT" \
    --disable-content-trust \
    -t ${NAME} \
    -f "$TMPFILE" \
    "$DIR"/../..

docker rm ${NAME}-tmp 2>/dev/null || true
echo "starting docker create"
docker create --name ${NAME}-tmp ${NAME}
echo "starting cleanup"
rm -rf "$DIR"/../output-"${1,,}"/
mkdir -p "$DIR"/../output-"${1,,}"/
docker cp ${NAME}-tmp:/output "$DIR"/../output-"${1,,}"/
mv "$DIR"/../output-"${1,,}"/output/* "$DIR"/../output-"${1,,}"/
rmdir "$DIR"/../output-"${1,,}"/output
docker rm ${NAME}-tmp
