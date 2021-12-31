#!/bin/bash
set -xe

iotginb=$GOPATH/src/inb
gosrc=$GOPATH/src
trtl=$iotginb/trtl


mkdir -p $GOPATH
rm -rf $gosrc
mkdir -p $iotginb/inb.git
cp -r /src/trtl $trtl
cd $trtl
export http_proxy=http://proxy-dmz.intel.com:911/
export https_proxy=http://proxy-dmz.intel.com:912/
export PATH=$GOROOT/bin:$PATH
scripts/set-up-trtl-deps

#scripts/build-trtl
CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 go build -o trtl
chmod +x trtl
rm -rf $wd/output
mkdir -p $wd/output/exe
cp trtl $wd/output/exe

