# base image with all dependencies for building
FROM registry.hub.docker.com/library/ubuntu:18.04 as base
include(`commands.base-setup.m4')

FROM base as packaging
COPY inbm-vision/packaging /src/packaging
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


# build a virtual environment for each agent to build from

# py3 venv
FROM base as venv-py3
WORKDIR /
RUN python3.8 -m venv /venv-py3 && \
    source /venv-py3/bin/activate && \
    pip3 install teamcity-messages virtualenv wheel -U
COPY inbm-lib /src/inbm-lib-editable
RUN source /venv-py3/bin/activate && \
    pip3.8 install -e /src/inbm-lib-editable

# ---inbc---

FROM venv-py3 as venv-inbc-py3
COPY inbc-program/requirements.txt /src/inbc-program/requirements.txt
WORKDIR /src/inbc-program
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt
COPY inbm-vision/version.txt /src/version.txt
COPY inbm-vision/packaging /src/packaging
COPY inbc-program /src/inbc-program

FROM venv-inbc-py3 as inbc-py3
RUN source /venv-py3/bin/activate && \
    mkdir -p /output && \
    set -o pipefail && \
    make deb-eval-py3 && cp -v dist/*.deb /output && \
    make rpm-ehl-py3 && cp -v dist/*.rpm /output


# ---vision agent---

FROM venv-py3 as venv-vision-py3
COPY inbm-vision/vision-agent/requirements.txt /src/vision-agent/requirements.txt
WORKDIR /src/vision-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt
COPY inbm-vision/version.txt /src/version.txt
COPY inbm-vision/vision-agent /src/vision-agent

FROM venv-vision-py3 as vision
COPY inbm-vision/packaging/ /src/packaging/
ARG VERSION
ARG COMMIT
RUN mkdir -p /src/vision-agent/fpm-template/usr/share/intel-manageability/ && \
    ( echo "Version: ${VERSION}" && echo "Commit: ${COMMIT}" ) >/src/vision-agent/fpm-template/usr/share/intel-manageability/inbm-vision-host-version.txt
RUN source /venv-py3/bin/activate && \
    mkdir -p /output && \
    set -o pipefail && \
    make deb-eval-py3  && cp -v dist/*.deb /output 


# ---node agent---

FROM venv-py3 as venv-node-py3
COPY inbm-vision/node-agent/requirements.txt /src/node-agent/requirements.txt
WORKDIR /src/node-agent
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt
COPY inbm-vision/version.txt /src/version.txt
COPY inbm-vision/node-agent /src/node-agent

FROM venv-node-py3 as node
COPY inbm-vision/packaging/ /src/packaging/
ARG VERSION
ARG COMMIT
RUN mkdir -p /src/node-agent/fpm-template/usr/share/intel-manageability/ && \
    ( echo "Version: ${VERSION}" && echo "Commit: ${COMMIT}" ) >/src/node-agent/fpm-template/usr/share/intel-manageability/inbm-vision-version.txt
RUN source /venv-py3/bin/activate && \
    mkdir -p /output && \
    set -o pipefail && \
    make deb-eval-py3  && cp -v dist/*.deb /output 

# ---flashless---


FROM venv-py3 as venv-flashless-py3
COPY inbm-vision/flashless-program/requirements.txt /src/flashless-program/requirements.txt
WORKDIR /src/flashless-program
RUN source /venv-py3/bin/activate && \
    pip3.8 install -r requirements.txt
COPY inbm-vision/version.txt /src/version.txt
COPY inbm-vision/packaging /src/packaging
COPY inbm-vision/flashless-program /src/flashless-program

FROM venv-flashless-py3 as flashless-py3
RUN source /venv-py3/bin/activate && \
    mkdir -p /output && \
    set -o pipefail && \
    make deb-eval-py3 && cp -v dist/*.deb /output && \
    mkdir -p /output/temp && \
    dpkg --extract /output/*.deb /output/temp && \
    cp /output/temp/usr/bin/flashless /output && \
    rm -r /output/*.deb /output/temp


# output container
FROM base as output
COPY --from=packaging /output /packaging
COPY --from=vision /output /vision
COPY --from=node /output /node
COPY --from=inbc-py3 /output /inbc
COPY --from=flashless-py3 /output /flashless
RUN mkdir -p /output && \
    cp -rv /vision/* \
    /node/* \
    /packaging/* \
	/inbc/* \
	/flashless/* \
    /output
COPY inbm-vision/installer/install-bc.sh /output
RUN chmod +x /output/install-bc.sh
COPY inbm-vision/installer/uninstall-bc.sh /output
RUN chmod +x /output/uninstall-bc.sh
