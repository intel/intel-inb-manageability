#!/bin/bash

# Assumptions:
# * run the script from the directory it lives in
# * grpcio-tools is installed

python -m grpc_tools.protoc -I. --python_out=cloudadapter/cloud/adapters --grpc_python_out=cloudadapter/cloud/adapters proto/inbs_sb.proto
sed -i 's/from proto import/from . import/' cloudadapter/cloud/adapters/proto/*.py
