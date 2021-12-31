#!/bin/bash
set -euxo pipefail

DOCKER_CONTENT_TRUST=0
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -x /usr/bin/pigz ]; then
    GZIP=/usr/bin/pigz
elif [ -x /usr/bin/gzip ]; then
    GZIP=/usr/bin/gzip
elif [ -x /bin/gzip ]; then
    GZIP=/bin/gzip
else
    echo pigz or gzip not found
    exit 1
fi 

NAME=inb

cd "$DIR"
rm -rf "$DIR"/output

# Run all checks and all Python unit tests
./build-check.sh
rsync -av output-check/ output/
rm -rf output-check/

# Build main output for Linux
./build-main.sh
rsync -av output-main/ output/
rm -rf output-main/

# rpmlite tgz/load tgz
( rm -rf "$DIR"/scratch-packaging # to avoid docker cache invalidation
  cp -r "$DIR"/packaging "$DIR"/scratch-packaging
  cd "$DIR"/scratch-packaging
rm -f docker-sample-container/sample-container.tgz
cd docker-sample-container && cp -v "$DIR"/output/*.rpm ./docker && docker build -t sample-container docker
: Creating temp container.
rm -f tmp-container.txt
TMP_CONTAINER=$(docker create sample-container /bin/true)
: Exporting, compressing temp container.
docker export "${TMP_CONTAINER}" | ${GZIP} >"$DIR"/output/sample-container.tgz
: Saving image
docker save sample-container | ${GZIP} >"$DIR"/output/sample-container-load.tgz
: Removing temp container.
docker rm "${TMP_CONTAINER}"
: Cleaning up
rm -rf "$DIR"/scratch-packaging
: Done. )

cp -v ../LICENSE "$DIR"/output
cp -v ../third-party-programs.txt "$DIR"/output/third-party-programs.txt

if [ -x tree ] ; then
    tree "$DIR"/output
fi

echo build.sh complete
