#!/bin/bash

# Assumptions:
# * grpcio-tools is installed via pip
# * mypy-protobuf is installed via pip
# * protoc is installed
# * go install github.com/envoyproxy/protoc-gen-validate@latest
# NOTE: to run mypy on generated code, need via pip: mypy>=0.910, types-protobuf>=0.1.14

set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo Generating Python proto files.
cd "$DIR/cloudadapter-agent"
python3 -m grpc_tools.protoc -I../proto --python_out=cloudadapter/pb --grpc_python_out=cloudadapter/pb --mypy_out=cloudadapter/pb ../proto/common/v1/common.proto
python3 -m grpc_tools.protoc -I../proto --python_out=cloudadapter/pb --grpc_python_out=cloudadapter/pb --mypy_out=cloudadapter/pb ../proto/inbs/v1/inbs_sb.proto

sed -i 's/ common.v1/ cloudadapter.pb.common.v1/' cloudadapter/pb/*/v1/*.py{,i}
sed -i 's/\[common.v1.common_pb2/\[cloudadapter.pb.common.v1.common_pb2/' cloudadapter/pb/*/v1/*.py{,i}
sed -i 's/ inbs.v1/ cloudadapter.pb.inbs.v1/' cloudadapter/pb/*/v1/*.py{,i}

echo "Generating golang proto files for inbs-mock."
cd "$DIR"/proto
protoc --go_out=inbs-mock \
       --go-grpc_out=inbs-mock \
       --go_opt=Mcommon/v1/common.proto=./pb \
       --go-grpc_opt=Mcommon/v1/common.proto=./pb \
       common/v1/common.proto
protoc --go_out=inbs-mock \
       --go-grpc_out=inbs-mock \
       --go_opt=Minbs/v1/inbs_sb.proto=./pb \
       --go-grpc_opt=Minbs/v1/inbs_sb.proto=./pb \
       --go_opt=Mcommon/v1/common.proto=./pb \
       --go-grpc_opt=Mcommon/v1/common.proto=./pb \
       inbs/v1/inbs_sb.proto
