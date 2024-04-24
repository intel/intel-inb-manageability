#!/bin/bash

# Assumes protoc for golang toolchain is installed
# Assumes script is run from script directory

ln -sf ../inbs_sb.proto inbs_sb.proto
protoc --go_out=. --go-grpc_out=. --go_opt=Minbs_sb.proto=./pb --go-grpc_opt=Minbs_sb.proto=./pb inbs_sb.proto
