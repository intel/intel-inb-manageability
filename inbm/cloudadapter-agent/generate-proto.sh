#!/bin/bash

# Assumptions:
# * grpcio-tools is installed via pip
# * mypy-protobuf is installed via pip
# * protoc is installed
# * go install github.com/envoyproxy/protoc-gen-validate@latest
# NOTE: to run mypy on generated code, need via pip: mypy>=0.910, types-protobuf>=0.1.14

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo Generating Python proto files.
cd "$DIR"
python -m grpc_tools.protoc -I. --python_out=cloudadapter/cloud/adapters --grpc_python_out=cloudadapter/cloud/adapters --mypy_out=cloudadapter/cloud/adapters proto/inbs_sb.proto
sed -i 's/from proto import/from . import/' cloudadapter/cloud/adapters/proto/*.py


echo "Generating golang proto files for inbs-mock."
cd "$DIR"/proto/inbs-mock
ln -sf ../inbs_sb.proto inbs_sb.proto
protoc --go_out=. --go-grpc_out=. --go_opt=Minbs_sb.proto=./pb --go-grpc_opt=Minbs_sb.proto=./pb inbs_sb.proto
