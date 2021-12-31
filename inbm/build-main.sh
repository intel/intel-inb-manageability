#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
"$DIR"/dockerfiles/build-Dockerfile.sh main

# tpm2 tools
( cd "$DIR"/tpm2-tools
./build.sh
cp -r debs-18.04/* "$DIR"/output-main/
cp -r debs-20.04/* "$DIR"/output-main/ )

( cd "$DIR"/output-main ;
  TAR_CONTENTS="./*-agent*.deb tpm2-tss*.deb tpm2-tools*.deb tpm2-abrmd*.deb trtl*.deb tpm-provision*.deb mqtt*.deb inbc*.deb"
    tar zcvf Intel-Manageability.preview.tar.gz $TAR_CONTENTS && \
	      rm -f $TAR_CONTENTS )
