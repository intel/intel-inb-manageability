FROM registry.hub.docker.com/arm64v8/ubuntu:20.04 as base-arm64v8
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
include(`commands.base-setup.m4')
COPY inbm-lib /src/inbm-lib-editable
RUN python3.11 -m venv /venv-py3 && \
    . /venv-py3/bin/activate && \
    pip3.11 install -U pip && \
    pip3.11 install -U wheel teamcity-messages virtualenv setuptools-rust
RUN . /venv-py3/bin/activate && rm -rf /output && \
    pip3.11 install -e /src/inbm-lib-editable
RUN rm /usr/lib/*/libreadline* # extra protection against libreadline in pyinstaller binaries

FROM registry.hub.docker.com/library/ubuntu:20.04 as base-x86_64
include(`commands.base-setup.m4')

# ------Build Agents for arm64------

define(`pyinstaller_kmb', `FROM base-arm64v8 as build-$1
WORKDIR /
COPY $4/requirements.txt /src/$1-$2/requirements.txt
RUN . /venv-py3/bin/activate && \
    pip3.11 install --upgrade pip && \
    pip3.11 install -r /src/$1-$2/requirements.txt && \
    if pip3.11 list | grep chardet ; then pip3.11 uninstall -y chardet ; fi # license issue
COPY inbm/packaging /src/packaging
COPY $4 /src/$1-$2
WORKDIR /src
RUN . /venv-py3/bin/activate && rm -rf /output && \
    mkdir -p /output/exe && \
    packaging/run-pyinstaller-py3.sh "$1-$2" "$1" && \
    cp -r "$1-$2/dist/$1" /output/exe/$1
')

pyinstaller_kmb(`inbm-dispatcher', `agent', `arm64v8', `inbm/dispatcher-agent')
pyinstaller_kmb(`inbm-diagnostic', `agent', `arm64v8', `inbm/diagnostic-agent')
pyinstaller_kmb(`inbm-cloudadapter', `agent', `arm64v8', `inbm/cloudadapter-agent')
pyinstaller_kmb(`inbm-telemetry', `agent', `arm64v8', `inbm/telemetry-agent')
pyinstaller_kmb(`inbm-configuration', `agent', `arm64v8', `inbm/configuration-agent')
pyinstaller_kmb(`inbc', `program', `arm64v8', 'inbc-program')

FROM registry.hub.docker.com/arm64v8/golang:1.20-buster as build-inb-provision-certs
COPY inbm/fpm/inb-provision-certs /inb-provision-certs
RUN cd /inb-provision-certs && go build . &&  rm -rf /output/ && mkdir /output && cp /inb-provision-certs/inb-provision-certs /output

FROM registry.hub.docker.com/arm64v8/golang:1.20-buster as build-inb-provision-cloud
COPY inbm/fpm/inb-provision-cloud /inb-provision-cloud
RUN cd /inb-provision-cloud && go build . &&  rm -rf /output/ && mkdir /output && cp /inb-provision-cloud/inb-provision-cloud /output

FROM registry.hub.docker.com/arm64v8/golang:1.20-buster as build-inb-provision-ota-cert
COPY inbm/fpm/inb-provision-ota-cert /inb-provision-ota-cert
RUN cd /inb-provision-ota-cert && go build . &&  rm -rf /output/ && mkdir /output && cp /inb-provision-ota-cert/inb-provision-ota-cert /output


FROM base-x86_64 as misc-rpms
WORKDIR /
RUN wget https://github.com/certifi/python-certifi/archive/refs/tags/2020.12.05.zip -O python-certifi-src-2020.12.05.zip
RUN gem install --no-document fpm -v 1.14.0
COPY inbm/fpm /src/fpm
WORKDIR /src/fpm
COPY --from=build-inb-provision-certs /output/inb-provision-certs /src/fpm/mqtt/template/usr/bin/inb-provision-certs
COPY --from=build-inb-provision-cloud /output/inb-provision-cloud /src/fpm/mqtt/template/usr/bin/inb-provision-cloud
COPY --from=build-inb-provision-ota-cert /output/inb-provision-ota-cert /src/fpm/mqtt/template/usr/bin/inb-provision-ota-cert
RUN mkdir -p /src/fpm/mqtt/template/usr/share/intel-manageability/third-party-programs.txt
COPY third-party-programs.txt /src/fpm/mqtt/template/usr/share/intel-manageability/third-party-programs.txt
COPY inbm/version.txt /src/version.txt
RUN mv /python-certifi-src-2020.12.05.zip /src/fpm/mqtt/template/usr/share/intel-manageability && \
    echo "The certifi source code is governed by the terms of the Mozilla Public License 2.0." >/src/fpm/mqtt/template/usr/share/intel-manageability/python-certifi-src-NOTICE.txt
RUN perl -pi -e 'chomp if eof' /src/version.txt
RUN rm -rf output/ && \
    mkdir -p output/ && \
    ./configure && \
    cat Makefile && \
    make clean
RUN cat Makefile && \
    make mqtt-rpm yocto-provision-rpm  && \
    mkdir -p /output/rpm && \
    mv output/mqtt-*rpm output/yocto-provision-*rpm /output/rpm

# --- trtl ---

FROM registry.hub.docker.com/arm64v8/golang:1.20-buster as trtl-build-arm64
WORKDIR /
ENV GOPATH /build/go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin
COPY inbm/trtl /src/trtl
WORKDIR /repo
RUN mkdir -p /build/go/src/iotg-inb && cp -r /src/trtl /build/go/src/iotg-inb
WORKDIR /build/go/src/iotg-inb/trtl
RUN scripts/set-up-trtl-deps
RUN scripts/build-trtl
# tests already run in x86_64 builds
COPY inbm/version.txt /build/go/src/iotg-inb/version.txt

FROM base-x86_64 as trtl-package-arm64
COPY --from=trtl-build-arm64 /build /build
WORKDIR /build/go/src/iotg-inb/trtl
RUN scripts/package-trtl rpm KMB
RUN rm -rf /output/ && mv ./output/ /output/


# ------Output Container for arm64------

FROM base-arm64v8 as output-arm64
COPY --from=build-inbm-dispatcher /output /agents
COPY --from=build-inbm-diagnostic /output /agents
COPY --from=build-inbm-telemetry /output /agents
COPY --from=build-inbm-configuration /output /agents
COPY --from=build-inbm-cloudadapter /output /agents
COPY --from=build-inbc /output /programs
COPY --from=misc-rpms /output /rpms
COPY --from=trtl-package-arm64 /output /trtl-arm64
RUN mkdir -p /output && \
    cp -rv \
    /agents/* \
    /programs/* \
    /rpms/* \
    /trtl-arm64/* \
    /output


FROM base-x86_64 as output-kmb

COPY --from=output-arm64 /output /input
RUN cp -r /input/rpm/*.rpm /input/
RUN mkdir -p /build
COPY inbm/version.txt /build/version.txt

WORKDIR /build
# ensure working directories exist
RUN mkdir -p /output/aarch64 && mkdir -p packaging/input && mkdir -p packaging/output && mkdir -p rename

# input now has rpms
RUN cp -v /input/*.rpm /output

# output now has all rpms

# generate makefile using configure
COPY inbm/packaging /build/packaging
WORKDIR /build
RUN cd packaging && \
    if [ -f configure ] ; then \
      ./configure ; \
    fi

RUN mkdir -p /output/aarch64 && mv -v /output/*.rpm /output/aarch64 &&  rm -f /output/aarch64/*agent*.rpm 

# build KMB arm64 agent exe RPMs
RUN rm -rf /output/aarch64/exe/*agent*.rpm
ARG VERSION
ARG COMMIT
RUN set -e && mkdir -p /build/inbm-dispatcher-agent/fpm-template/usr/share/intel-manageability/ && \
    ( echo "Version: ${VERSION}" && echo "Commit: ${COMMIT}" ) >/build/inbm-dispatcher-agent/fpm-template/usr/share/intel-manageability/inbm-version.txt
COPY inbm/dispatcher-agent /build/inbm-dispatcher-agent
COPY inbm/telemetry-agent /build/inbm-telemetry-agent
COPY inbm/diagnostic-agent /build/inbm-diagnostic-agent
COPY inbm/configuration-agent /build/inbm-configuration-agent
COPY inbm/cloudadapter-agent /build/inbm-cloudadapter-agent
WORKDIR /build
RUN for i in inbm-dispatcher inbm-telemetry inbm-diagnostic inbm-configuration inbm-cloudadapter; do \
    set -e && cd ${i}-agent && \
    rm -rf exe dist && \
    mkdir -p exe && \
    mkdir -p dist && \
    cp -r /input/exe/*$i exe/ && \
    ../packaging/build-agent-exe-py3.sh $i rpm KMB agent && \
    mv -v dist/*.rpm /output/aarch64 && \
    cd .. ; \
    done

COPY inbc-program /build/inbc-program
WORKDIR /build
RUN for i in inbc; do \
      cd ${i}-program && \
      rm -rf exe dist && \
      mkdir -p exe && \
      mkdir -p dist && \
      cp -r /input/exe/$i exe/ && \
      ../packaging/build-agent-exe-py3.sh $i rpm KMB program && \
      mv -v dist/*.rpm /output/aarch64 && \
      cd .. ; \
    done


WORKDIR /build
COPY inbm/Changelog.md /build/Changelog.md
RUN mkdir -p KMB && mv -v /output/aarch64/* KMB && rm -rf /output
RUN set -e && perl -pi -e 'chomp if eof' /build/version.txt && \
    VERSION=$(cat /build/version.txt) && \
    cp -v Changelog.md KMB && \
    cd KMB && \
    for file in *.rpm ; do \
      TAR="$(basename "$file" .rpm).tar" && \
      fpm -s rpm -t tar -p "$TAR" "$file"  && rm -fv "$file" && \
      tar --delete -f "$TAR" ./.scripts && \
      gzip -v "$TAR" && \
      rm -fv "$TAR" ; \   
    done && \
    for i in inbm-cloudadapter-agent inbm-dispatcher-agent inbm-diagnostic-agent inbm-telemetry-agent inbm-configuration-agent inbc-program trtl; do \
      mv -v "$i"-"$VERSION"*.tar.gz "$i"-"$VERSION"-1.tar.gz ; \
    done
RUN mkdir -p /output && cp -r /build/KMB /output


