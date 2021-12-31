FROM registry.hub.docker.com/curlimages/curl:7.74.0  as ibmtpm1332
RUN curl -L https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1332.tar.gz >/tmp/ibmtpm1332.tar.gz && \
    sha256sum /tmp/ibmtpm1332.tar.gz | grep -q 8e8193af3d11d9ff6a951dda8cd1f4693cb01934a8ad7876b84e92c6148ab0fd

FROM registry.hub.docker.com/library/ubuntu:18.04 as builder-18.04
HEALTHCHECK NONE

# generic build tools
RUN apt-get  update &&\
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

RUN gem install --no-document fpm -v 1.11.0


# Intel-tpm2-specific deps
RUN apt-get update &&\
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
    libjson-c-dev \
    uuid-dev \
    doxygen && \
    apt-get clean

RUN DEBIAN_FRONTEND=noninteractive apt-get -y install libglib2.0-dev


ENV PATH=/tpm2/ibmtpm1332/src:$PATH
WORKDIR /tpm2

# Get source code
COPY --from=ibmtpm1332 /tmp/ibmtpm1332.tar.gz /ibmtpm1332.tar.gz

ENV TPM2TSSVER=2.4.6
ENV TPM2TSS=tpm2-tss-2.4.6.tar.gz
RUN curl -L https://github.com/tpm2-software/tpm2-tss/releases/download/${TPM2TSSVER}/${TPM2TSS} >${TPM2TSS} && \
    sha256sum ${TPM2TSS} | grep -q 20e6da532a7ef90c8e50cca51f276053ec505eee0167c18e2b07c1e747118b58 

ENV TPM2ABRMDVER=2.4.0
ENV TPM2ABRMD=tpm2-abrmd-2.4.0.tar.gz
RUN curl -L https://github.com/tpm2-software/tpm2-abrmd/releases/download/${TPM2ABRMDVER}/${TPM2ABRMD} >${TPM2ABRMD} && \
    sha256sum ${TPM2ABRMD} | grep -q 044522f1568f3d5334878f0564f808ec9fdd6a4ac5d0f3bd75ae6f2c7551a96c

ENV TPM2TOOLSVER=4.3.2
ENV TPM2TOOLS=tpm2-tools-4.3.2.tar.gz
RUN curl -L https://github.com/tpm2-software/tpm2-tools/releases/download/${TPM2TOOLSVER}/${TPM2TOOLS} >${TPM2TOOLS} && \
    sha256sum ${TPM2TOOLS} | grep -q e2802d4093a24b2c65b1f913d0f4c68eadde9b8fd8a9b7a3b17a6e50765e8350

# compile and install tpm2-tss
RUN tar zxvf ${TPM2TSS} && \
    cd tpm2-tss-${TPM2TSSVER} && \
    rm -rf ./build && \
    mkdir ./build && \
    cd ./build && \
    ../configure --prefix=/usr \
      --with-udevrulesdir=/lib/udev/rules.d && \
    make -j $(nproc) && \
    make install

# compile IBM's Software TPM 2.0
RUN rm -rf ibmtpm1332 && mkdir -p ibmtpm1332 && \
    (cd ibmtpm1332 && gzip -cd /ibmtpm1332.tar.gz | cpio -iv -R root:root) && \
    make -C ibmtpm1332/src -j $(nproc)

RUN mkdir -p  /debs
COPY ldconfig.sh /tpm2/

# compile and install tpm2-abrmd
RUN tar zxvf ${TPM2ABRMD} && \
    cd tpm2-abrmd-${TPM2ABRMDVER} && \
    ./configure \
      --prefix=/usr \
      --with-udevrulesdir=/lib/udev/rules.d \
      --with-dbuspolicydir=/etc/dbus-1/system.d \
      --with-systemdsystemunitdir=/lib/systemd/system \
      --with-systemdpresetdir=/lib/systemd/system-preset && \
    make -j $(nproc) && \
    make install

# compile and install tpm2-tools
RUN tar zxvf ${TPM2TOOLS} && \
    cd tpm2-tools-${TPM2TOOLSVER} && \
    ./configure --prefix=/usr --with-tcti-abrmd && \
    make -j $(nproc) && \
    make install

# package tpm2-tss
COPY tss-install.sh /tpm2/
RUN cd tpm2-tss-${TPM2TSSVER}/build && make DESTDIR=/tpm2/tpm2-tss install && \
    NAME=tpm2-tss && \
    VERSION=${TPM2TSSVER} && \
    ITERATION=1 && \
    rm -f ${NAME}-${VERSION}-${ITERATION}.deb && \
    cd /tpm2 && \
    ls -l && \
    fpm -t deb \
        --after-install tss-install.sh \
        --iteration ${ITERATION} \
        -s dir \
        -C tpm2-tss \
        -p ${NAME}-${VERSION}-${ITERATION}.deb \
        -f \
        -n ${NAME} \
        -v ${VERSION} \
        --no-depends \
        --no-auto-depends \
        -a all \
        -m none \
        . && \
    rm -rf tpm2-abrmd && \
    mv -v *.deb /debs

# package tpm2-abrmd
COPY tpm2-abrmd-after-install.sh /tpm2
COPY tpm2-abrmd-before-remove.sh /tpm2
RUN cd tpm2-abrmd-${TPM2ABRMDVER} && make DESTDIR=/tpm2/tpm2-abrmd install && cd .. && \
    NAME=tpm2-abrmd && \
    VERSION=${TPM2ABRMDVER} && \
    ITERATION=1 && \
    rm -f ${NAME}-${VERSION}-${ITERATION}.deb && \
    ls -l && \
    fpm -t deb \
        --after-install tpm2-abrmd-after-install.sh \
        --before-remove tpm2-abrmd-before-remove.sh \
        --iteration ${ITERATION} \
        -s dir \
        -C tpm2-abrmd \
        -p ${NAME}-${VERSION}-${ITERATION}.deb \
        -f \
        -n ${NAME} \
        -v ${VERSION} \
        -d tpm2-tss \
        -d libglib2.0-0 \
        -d udev \
        --no-auto-depends \
        -a all \
        -m none \
        . && \
    rm -rf tpm2-abrmd && \
    mv -v *.deb /debs

# package tpm2-tools
RUN cd tpm2-tools-${TPM2TOOLSVER} && make DESTDIR=/tpm2/tpm2-tools install && cd .. && \
    NAME=tpm2-tools && \
    VERSION=${TPM2TOOLSVER} && \
    ITERATION=1 && \
    rm -f ${NAME}-${VERSION}-${ITERATION}.deb && \
    ls -l && \
    fpm -t deb \
        --after-install ldconfig.sh \
        --iteration ${ITERATION} \
        -s dir \
        -C tpm2-tools \
        -p ${NAME}-${VERSION}-${ITERATION}.deb \
        -f \
        -n ${NAME} \
        -v ${VERSION} \
        -d tpm2-tss \
        --no-auto-depends \
        -a all \
        -m none \
        . && \
    rm -rf tpm2-tools && \
    mv -v *.deb /debs

# compile IBM's Software TPM 2.0
RUN rm -rf ibmtpm1332 && mkdir -p ibmtpm1332 && \
    (cd ibmtpm1332 && gzip -cd /ibmtpm1332.tar.gz | cpio -iv -R root:root) && \
    make -C ibmtpm1332/src -j $(nproc)

RUN mkdir -p  /debs
COPY ldconfig.sh /tpm2/

# package IBM's Software TPM 2.0
COPY tpm2-simulator.service /tpm2
COPY tpm2-simulator-after-install.sh /tpm2
COPY tpm2-simulator-before-remove.sh /tpm2
RUN mkdir -p tpm2-simulator/var/tpm2-simulator && \
    mkdir -p tpm2-simulator/usr/bin && \
    cp ibmtpm1332/src/tpm_server tpm2-simulator/usr/bin && \
    mkdir -p tpm2-simulator/lib/systemd/system && \
    cp tpm2-simulator.service tpm2-simulator/lib/systemd/system && \
    NAME=tpm2-simulator18.04 && \
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

RUN gem install --no-document fpm -v 1.11.0

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

# package IBM's Software TPM 2.0
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

FROM jrei/systemd-ubuntu:18.04
RUN cat /etc/apt/sources.list

# Intel-tpm2-specific deps
RUN apt-get update &&\
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends -y install \
    libglib2.0 \
    libssl1.0 \
    sudo \
    udev \
    dbus && \
    apt-get clean

COPY --from=builder-18.04 /debs/ /debs-18.04/
COPY --from=builder-20.04 /debs/ /debs-20.04/

COPY tpm2-tools-test.sh /
COPY interactive-startup.sh /
