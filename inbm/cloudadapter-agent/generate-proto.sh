#!/bin/bash

# Assumptions:
# * grpcio-tools is installed
# * protoc is installed

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

python -m grpc_tools.protoc -I. --python_out=cloudadapter/cloud/adapters --grpc_python_out=cloudadapter/cloud/adapters proto/inbs_sb.proto
sed -i 's/from proto import/from . import/' cloudadapter/cloud/adapters/proto/*.py

cd "$DIR"/proto/inbs-mock
ln -sf ../inbs_sb.proto inbs_sb.proto
protoc --go_out=. --go-grpc_out=. --go_opt=Minbs_sb.proto=./pb --go-grpc_opt=Minbs_sb.proto=./pb inbs_sb.proto
