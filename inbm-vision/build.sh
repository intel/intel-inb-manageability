#!/bin/bash
set -euxo pipefail

DOCKER_CONTENT_TRUST=0
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

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

NAME=bit-creek

perl -pi -e 'chomp if eof' version.txt

rm -rf "$DIR"/output

# Run all checks and all Python unit tests
./build-check.sh
rsync -av output-check/ output/
rm -rf output-check/

# Build main output for Linux
./build-main.sh
rsync -av output-main/ output/
rm -rf output-main/

cp -v ../LICENSE "$DIR"/output
cp -v ../third-party-programs.txt "$DIR"/output/third-party-programs.txt

if [ -x tree ] ; then
    tree "$DIR"/output
fi

echo build.sh complete
