#!/bin/bash
set -euxo pipefail

DOCKER_CONTENT_TRUST=0
export DOCKER_BUILDKIT=1
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

DOCKER_NAME=inb-snyk

# pre-install inbm-lib skeleton to speed python scans
rm -rf inbm-lib
cp -r "$DIR"/../inbm-lib .
touch inbm-lib/README.md

docker build \
    --build-arg HTTP_PROXY=${HTTP_PROXY:-} \
    --build-arg http_proxy=${http_proxy:-} \
    --build-arg HTTPS_PROXY=${HTTPS_PROXY:-} \
    --build-arg https_proxy=${https_proxy:-} \
    --build-arg NO_PROXY=${NO_PROXY:-} \
    --build-arg no_proxy=${no_proxy:-} \
    --disable-content-trust \
    -t ${DOCKER_NAME} \
    -f "$DIR"/Dockerfile "$DIR"

export NO_PROXY=$NO_PROXY,snyk.devtools.intel.com

scan_python () {
    docker run -e HTTP_PROXY -e HTTPS_PROXY -e NO_PROXY -e SNYK_ORG -e SNYK_TOKEN -e SNYK_API -v $DIR/..:/repository "$DOCKER_NAME" bash -x /scan-python.sh "$@"
}

scan_golang () {
    docker run -e HTTP_PROXY -e HTTPS_PROXY -e NO_PROXY -e SNYK_ORG -e SNYK_TOKEN -e SNYK_API -v $DIR/..:/repository "$DOCKER_NAME" bash -x /scan-golang.sh "$@"
}

rm -rf "$DIR"/results
mkdir -p "$DIR"/results

fail=0
scan_golang /repository/inbm/trtl trtl  >"$DIR"/results/snyk-trtl.html || fail=1
scan_golang /repository/inbm/fpm/inb-provision-cloud inb-provision-cloud >"$DIR"/results/snyk-inb-provision-cloud.html || fail=1
scan_golang /repository/inbm/fpm/inb-provision-certs inb-provision-certs >"$DIR"/results/snyk-inb-provision-certs.html || fail=1

for i in dispatcher diagnostic cloudadapter configuration telemetry ; do 
    scan_python /repository/inbm/$i-agent $i-agent >"$DIR"/results/snyk-$i-agent.html || fail=1
done

for i in vision node ; do
    scan_python /repository/inbm-vision/$i-agent $i-agent  >"$DIR"/results/snyk-$i-agent.html || fail=1
done

scan_python /repository/inbm-vision/flashless-program flashless-program  >"$DIR"/results/snyk-flashless-program.html || fail=1
scan_python /repository/inbc-program inbc-program >"$DIR"/results/snyk-inbc-program.html || fail=1


cat "$DIR"/results/snyk-*.html >"$DIR"/results/all-in-one-snyk.html
exit $fail
