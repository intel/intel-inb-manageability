# Copyright (c) 2021-2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM registry.hub.docker.com/curlimages/curl:7.74.0  as ibmtpm1332
RUN curl -L https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1332.tar.gz >/tmp/ibmtpm1332.tar.gz && \
    sha256sum /tmp/ibmtpm1332.tar.gz | grep -q 8e8193af3d11d9ff6a951dda8cd1f4693cb01934a8ad7876b84e92c6148ab0fd

FROM ubuntu:20.04 as builder-20.04

# generic build tools
RUN apt-get update &&\
    DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
        ca-certificates \
        libssl-dev \
        curl \
        build-essential \
        vim \
        git \
        ruby-dev \
        rubygems \
        cpio \
        sudo &&  \
    apt-get clean

RUN gem install --no-document fpm -v 1.14.0

# Intel-tpm2-specific deps
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends -y install \
    autoconf-archive \
    libcmocka0 \
    libcmocka-dev \
    libssl-dev \
    pkg-config \
    gcc \
    g++ \
    m4 \
    libtool \
    automake \
    python \
    autoconf \
    libdbus-1-dev \
    libgcrypt20-dev \
    libcurl4-openssl-dev \
    liburiparser-dev \
    doxygen && \
    apt-get clean

RUN DEBIAN_FRONTEND=noninteractive apt-get -y install libglib2.0-dev tpm2-abrmd tpm2-tools

ENV PATH=/tpm2/ibmtpm1332/src:$PATH
WORKDIR /tpm2

# Get source code
COPY --from=ibmtpm1332 /tmp/ibmtpm1332.tar.gz /ibmtpm1332.tar.gz

# compile IBM's Software TPM 2.0
RUN mkdir ibmtpm1332 && \
    (cd ibmtpm1332 && gzip -cd /ibmtpm1332.tar.gz | cpio -iv -R root:root) && \
    make -C ibmtpm1332/src -j $(nproc)

RUN mkdir -p  /debs
COPY ldconfig.sh /tpm2/

# package IBM's Software TPM 2.0 simulator
COPY tpm2-simulator.service /tpm2
COPY tpm2-simulator-after-install.sh /tpm2
COPY tpm2-simulator-before-remove.sh /tpm2
RUN mkdir -p tpm2-simulator/var/tpm2-simulator && \
    mkdir -p tpm2-simulator/usr/bin && \
    cp ibmtpm1332/src/tpm_server tpm2-simulator/usr/bin && \
    mkdir -p tpm2-simulator/lib/systemd/system && \
    cp tpm2-simulator.service tpm2-simulator/lib/systemd/system && \
    NAME=tpm2-simulator20.04 && \
    VERSION=0.1332 && \
    ITERATION=1 && \
    rm -f ${NAME}-${VERSION}-${ITERATION}.deb && \
    ls -l && \
    fpm -t deb \
        --after-install tpm2-simulator-after-install.sh \
        --before-remove tpm2-simulator-before-remove.sh \
        --iteration ${ITERATION} \
        -s dir \
        -C tpm2-simulator \
        -p ${NAME}-${VERSION}-${ITERATION}.deb \
        -f \
        -n ${NAME} \
        -v ${VERSION} \
        --no-depends \
        --no-auto-depends \
        -a all \
        -m none \
        . && \
    rm -rf tpm2-simulator && \
    mv -v *.deb /debs

FROM ubuntu:20.04
RUN cat /etc/apt/sources.list

COPY --from=builder-20.04 /debs/ /debs-20.04/
