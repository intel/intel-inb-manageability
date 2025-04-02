# SPDX-FileCopyrightText: (C) 2024-2025 Intel Corporation
# SPDX-License-Identifier: LicenseRef-Intel
VERSION 0.8

LOCALLY
ARG http_proxy=$(echo $http_proxy)
ARG https_proxy=$(echo $https_proxy)
ARG no_proxy=$(echo $no_proxy)
ARG HTTP_PROXY=$(echo $HTTP_PROXY)
ARG HTTPS_PROXY=$(echo $HTTPS_PROXY)
ARG NO_PROXY=$(echo $NO_PROXY)
ARG REGISTRY

FROM ${REGISTRY}golang:1.24.1-alpine3.21
ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy
ENV no_proxy=$no_proxy
ENV HTTP_PROXY=$HTTP_PROXY
ENV HTTPS_PROXY=$HTTPS_PROXY
ENV NO_PROXY=$NO_PROXY

all:
    BUILD +build
    BUILD +test
    BUILD +lint


fetch-golang:
    RUN apk add curl && curl -fsSLO https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
    SAVE ARTIFACT go1.24.1.linux-amd64.tar.gz

build:
    BUILD +generate-proto
    BUILD +build-inbc
    BUILD +build-inbd

golang-base:
    RUN apk add --no-cache protoc protobuf-dev libprotobuf curl gcc musl-dev && \
        go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28 && \
        go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2 && \
        go install github.com/bufbuild/buf/cmd/buf@v1.50.1 && \
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.7
    WORKDIR /work
    COPY go.mod .
    COPY go.sum .
    RUN go mod download # for caching
    COPY cmd/ ./cmd
    COPY pkg/ ./pkg
    COPY proto/ ./proto
    COPY internal/ ./internal

lint:
    FROM +golang-base
    WORKDIR /work
    RUN --mount=type=cache,target=/root/.cache \
        golangci-lint run ./...
    
test:
    BUILD +run-golang-unit-tests
    BUILD +lint

run-golang-unit-tests:
    FROM +golang-base
    
    # Run tests for all packages, generating coverage for internal/ only
    RUN --mount=type=cache,target=/root/.cache/go-build \
        CGO_ENABLED=1 go test -race -shuffle on -short ./... \
        -coverpkg=./internal/... -coverprofile=cover.out
    
    # Enforce minimum coverage threshold for internal/ directory
    RUN COVERAGE=$(go tool cover -func=cover.out | awk '/total:/ {print $3}' | tr -d '%') && MIN_COVERAGE=56.5 && echo "Total Coverage for internal/: $COVERAGE%" && echo "Minimum Required Coverage: $MIN_COVERAGE%" && awk -v coverage="$COVERAGE" -v min="$MIN_COVERAGE" 'BEGIN {if (coverage < min) {print "Coverage " coverage "% is below " min "%"; exit 1} else {print "Coverage " coverage "% meets the requirement."; exit 0}}'
    SAVE ARTIFACT cover.out AS LOCAL build/cover.out

    
generate-proto:
    FROM +golang-base
    COPY ./buf.gen.yaml .
    COPY ./buf.yaml .

    RUN buf generate
    SAVE ARTIFACT proto AS LOCAL ./proto
    SAVE ARTIFACT pkg/api/inbd AS LOCAL ./pkg/api/inbd

build-inbc:
    FROM +golang-base
    ARG version='0.0.0-unknown'
    RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOARCH=amd64 GOOS=linux \
        go build -trimpath -o build/inbc \
            -ldflags "-s -w -extldflags '-static' -X main.Version=$version" \
            ./cmd/inbc
    SAVE ARTIFACT build/inbc AS LOCAL ./build/inbc

build-inbd:
    FROM +golang-base
    ARG version='0.0.0-unknown'
    RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOARCH=amd64 GOOS=linux \
        go build -trimpath -o build/inbd \
            -ldflags "-s -w -extldflags '-static' -X main.Version=$version" \
            ./cmd/inbd
    SAVE ARTIFACT build/inbd AS LOCAL ./build/inbd
