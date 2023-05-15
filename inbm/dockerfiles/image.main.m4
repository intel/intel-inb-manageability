# base image with all dependencies for building
FROM registry.hub.docker.com/library/ubuntu:20.04 as base
include(`commands.base-setup.m4')


# build a virtual environment for each agent to build from

# py3 venv
FROM base as venv-py3-x86_64
WORKDIR /
RUN python3.8 -m venv /venv-py3 && \
    source /venv-py3/bin/activate && \
    pip3.8 install teamcity-messages virtualenv  wheel -U
COPY inbm/version.txt /src/version.txt
RUN perl -pi -e 'chomp if eof' /src/version.txt
COPY inbm-lib /src/inbm-lib-editable
RUN source /venv-py3/bin/activate && \
    pip3.8 install -e /src/inbm-lib-editable
RUN rm /usr/lib/x86_64-linux-gnu/libreadline* # extra protection against libreadline in pyinstaller binaries
RUN rm /usr/lib/x86_64-linux-gnu/libuuid.so.1 /usr/lib/x86_64-linux-gnu/libuuid.so.1.3.0

# ---inbc-program---

FROM venv-py3-x86_64 as venv-inbc-py3
COPY inbc-program/requirements.txt /src/inbc-program/requirements.txt
WORKDIR /src/inbc-program
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt
COPY inbm/version.txt /src/version.txt
COPY inbm/packaging /src/packaging
COPY inbc-program /src/inbc-program

FROM venv-inbc-py3 as inbc-py3
RUN source /venv-py3/bin/activate && \
    mkdir -p /output && \
    set -o pipefail && \
    make deb-eval-py3 && cp -v dist/*.deb /output && \
    make rpm-ehl-py3 && cp -v dist/*.rpm /output

# ---diagnostic agent---

FROM venv-py3-x86_64 as venv-diagnostic-py3
COPY inbm/diagnostic-agent/requirements.txt /src/diagnostic-agent/requirements.txt
WORKDIR /src/diagnostic-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt
COPY inbm/packaging /src/packaging
COPY inbm/diagnostic-agent /src/diagnostic-agent

FROM venv-diagnostic-py3 as diagnostic-py3
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    make deb-eval-py3 && cp -v dist/*.deb /output && \
    make rpm-ehl-py3 && cp -v dist/*.rpm /output


# ---dispatcher agent---

FROM venv-py3-x86_64 as venv-dispatcher-py3
COPY inbm/dispatcher-agent/requirements.txt /src/dispatcher-agent/requirements.txt
WORKDIR /src/dispatcher-agent
RUN source /venv-py3/bin/activate && \
    ln -sf /usr/bin/pip /usr/bin/pip3 && \
    pip3.8 install --upgrade pip && \
    pip3.8 install setuptools-rust && \
    pip3.8 install -r requirements.txt && \
    pip3.8 uninstall -y chardet # license issue

COPY inbm/packaging /src/packaging
COPY inbm/dispatcher-agent /src/dispatcher-agent
ARG VERSION
ARG COMMIT
RUN mkdir -p /src/dispatcher-agent/fpm-template/usr/share/intel-manageability/ && \
    ( echo "Version: ${VERSION}" && echo "Commit: ${COMMIT}" ) >/src/dispatcher-agent/fpm-template/usr/share/intel-manageability/inbm-version.txt
FROM venv-dispatcher-py3 as dispatcher-py3
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \
    make deb-eval-py3 && cp -v dist/*.deb /output && \
    make rpm-ehl-py3 && cp -v dist/*.rpm /output


# ---cloudadapter agent---

FROM venv-py3-x86_64 as venv-cloudadapter-py3
COPY inbm/cloudadapter-agent/requirements.txt /src/cloudadapter-agent/requirements.txt
WORKDIR /src/cloudadapter-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt && \
    pip3.8 uninstall -y chardet # license issue
COPY inbm/packaging /src/packaging
COPY inbm/cloudadapter-agent /src/cloudadapter-agent

FROM venv-cloudadapter-py3 as cloudadapter-py3
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \    
    make deb-eval-py3 && cp -v dist/*.deb /output && \
    make rpm-ehl-py3 && cp -v dist/*.rpm /output


# ---telemetry agent---

FROM venv-py3-x86_64 as venv-telemetry-py3
COPY inbm/telemetry-agent/requirements.txt /src/telemetry-agent/requirements.txt
WORKDIR /src/telemetry-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt
COPY inbm/packaging /src/packaging
COPY inbm/telemetry-agent /src/telemetry-agent

FROM venv-telemetry-py3 as telemetry-py3
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \    
    make deb-eval-py3 && cp -v dist/*.deb /output && \
    make rpm-ehl-py3 && cp -v dist/*.rpm /output

# ---configuration agent---

FROM venv-py3-x86_64 as venv-configuration-py3
COPY inbm/configuration-agent/requirements.txt /src/configuration-agent/requirements.txt
WORKDIR /src/configuration-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt
COPY inbm/packaging /src/packaging
COPY inbm/configuration-agent /src/configuration-agent

FROM venv-configuration-py3 as configuration-py3
RUN source /venv-py3/bin/activate && \
    mkdir -p /output/coverage && \
    set -o pipefail && \    
    make deb-eval-py3 && cp -v dist/*.deb /output && \
    make rpm-ehl-py3 && cp -v dist/*.rpm /output



# ---trtl---

FROM registry.hub.docker.com/library/golang:1.20-buster as trtl-build
WORKDIR /
ENV GOPATH /build/go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin
RUN mkdir -p /build/go/bin && \
    curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
# TODO run realdocker tests later in integration or reloaded
COPY inbm/trtl /src/trtl
WORKDIR /repo
RUN mkdir -p /build/go/src/iotg-inb && cp -r /src/trtl /build/go/src/iotg-inb
WORKDIR /build/go/src/iotg-inb/trtl
RUN scripts/set-up-trtl-deps
RUN scripts/build-trtl

RUN go get -t github.com/stretchr/testify/assert

RUN scripts/test-trtl
COPY inbm/version.txt /build/go/src/iotg-inb/version.txt

FROM base as trtl-package
COPY --from=trtl-build /build /build
WORKDIR /build/go/src/iotg-inb/trtl
RUN scripts/package-trtl deb EVAL
RUN scripts/package-trtl rpm EHL
RUN rm -rf /output/ && mv ./output/ /output/

# --inb-provision-certs-

FROM registry.hub.docker.com/library/golang:1.20-buster as inb-provision-certs
COPY inbm/fpm/inb-provision-certs /inb-provision-certs
RUN cd /inb-provision-certs && go build . &&  rm -rf /output/ && mkdir /output && cp /inb-provision-certs/inb-provision-certs /output/inb-provision-certs

# --inb-provision-cloud-

FROM registry.hub.docker.com/library/golang:1.20-buster as inb-provision-cloud
COPY inbm/fpm/inb-provision-cloud /inb-provision-cloud
RUN cd /inb-provision-cloud && go test . && go build . &&  rm -rf /output/ && mkdir /output && cp /inb-provision-cloud/inb-provision-cloud /output/inb-provision-cloud

# --inb-provision-ota-cert-

FROM registry.hub.docker.com/library/golang:1.20-buster as inb-provision-ota-cert
COPY inbm/fpm/inb-provision-ota-cert /inb-provision-ota-cert
RUN cd /inb-provision-ota-cert && go build . &&  rm -rf /output/ && mkdir /output && cp /inb-provision-ota-cert/inb-provision-ota-cert /output/inb-provision-ota-cert

# --packaging--

FROM base as packaging
COPY inbm/packaging /src/packaging
WORKDIR /src/packaging
RUN rm -rf output/ && \
    mkdir -p output/ && \
    ./configure && \
    make clean
RUN make build && \
    mkdir -p /output/coverage && \
    mv output/* /output
WORKDIR /repo
RUN mkdir -p output/certs && \
    mkdir -p output/mqtt && \
    mv output/* /output
WORKDIR /src/packaging
RUN cp -v docker-sample-container/docker/certs/succeed_rpm_key.pem /output

FROM base as fpm
WORKDIR /
RUN wget https://github.com/certifi/python-certifi/archive/refs/tags/2020.12.05.zip -O python-certifi-src-2020.12.05.zip
COPY inbm/fpm /src/fpm
WORKDIR /src/fpm
COPY --from=inb-provision-certs /output/inb-provision-certs /src/fpm/mqtt/template/usr/bin/inb-provision-certs
COPY --from=inb-provision-cloud /output/inb-provision-cloud /src/fpm/mqtt/template/usr/bin/inb-provision-cloud
COPY --from=inb-provision-ota-cert /output/inb-provision-ota-cert /src/fpm/mqtt/template/usr/bin/inb-provision-ota-cert
RUN mkdir -p /src/fpm/mqtt/template/usr/share/intel-manageability
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
RUN make build && \
    mkdir -p /output/coverage && \
    mv output/* /output

# output container
FROM registry.hub.docker.com/library/ubuntu:20.04 as output-main
COPY --from=packaging /output /packaging
COPY --from=inbc-py3 /output /inbc
COPY --from=diagnostic-py3 /output /diagnostic
COPY --from=cloudadapter-py3 /output /cloudadapter
COPY --from=dispatcher-py3 /output /dispatcher
COPY --from=telemetry-py3 /output /telemetry
COPY --from=configuration-py3 /output /configuration
COPY --from=trtl-package /output /trtl
COPY --from=fpm /output /fpm
RUN mkdir -p /output/ && \
    cp -rv /packaging/* \
    /inbc/* \
    /diagnostic/* \
    /cloudadapter/* \
    /dispatcher/* \
    /telemetry/* \
    /configuration/* \
    /trtl/* \
    /fpm/* \
    /output
COPY inbm/installer/install-tc.sh /output
RUN chmod +x /output/install-tc.sh
COPY inbm/installer/uninstall-tc.sh /output
RUN chmod +x /output/uninstall-tc.sh
COPY inbm/packaging/misc-files/* /output/
