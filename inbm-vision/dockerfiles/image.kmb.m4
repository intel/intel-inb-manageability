FROM arm64v8/ubuntu:18.04 as base-arm64v8
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
include(`commands.base-setup.m4')
COPY inbm-lib /src/inbm-lib-editable
RUN python3.8 -m venv /venv-py3 && \
    . /venv-py3/bin/activate && \
    pip3.8 install wheel && \
    pip3.8 install teamcity-messages virtualenv
RUN . /venv-py3/bin/activate && \
    pip3.8 install -e /src/inbm-lib-editable

FROM registry.hub.docker.com/library/ubuntu:16.04 as base-x86_64
include(`commands.base-setup.m4')

# ------Build Agents for arm64------

define(`pyinstaller_kmb', `FROM base-arm64v8 as build-$1
WORKDIR /
COPY inbm-vision/$4/requirements.txt /src/$4/requirements.txt
RUN . /venv-py3/bin/activate && \
    pip3.8 install -r /src/$4/requirements.txt
COPY inbm-vision/packaging /src/packaging
COPY inbm-vision/$4 /src/$4
WORKDIR /src
RUN . /venv-py3/bin/activate && rm -rf /output && \
    mkdir -p /output/exe && \
    packaging/run-pyinstaller-py3.sh "$1-$2" "$1" && \
    cp -r "$4/dist/$1" /output/exe/$1
')

pyinstaller_kmb(`inbm-node', `agent', `arm64v8', `node-agent')
pyinstaller_kmb(`inbm-vision', `agent', `arm64v8', `vision-agent')

# ------Output Container for arm64------

FROM base-x86_64 as output-arm64
COPY --from=build-inbm-node /output /agents
COPY --from=build-inbm-vision /output /agents
RUN mkdir -p /output && \
    cp -rv \
    /agents/* \
    /output


FROM base-x86_64 as output-kmb

COPY --from=output-arm64 /output /input
RUN mkdir -p /build
COPY inbm-vision/version.txt /build/version.txt

WORKDIR /build
# ensure working directories exist
RUN mkdir -p /output/aarch64
RUN mkdir -p packaging/input
RUN mkdir -p packaging/output
RUN mkdir -p rename

# generate makefile using configure
COPY inbm-vision/packaging /build/packaging
WORKDIR /build
RUN cd packaging && \
    if [ -f configure ] ; then \
      ./configure ; \
    fi

RUN mkdir -p /output/aarch64
RUN rm -f /output/aarch64/*.rpm

# build KMB arm64 agent exe RPMs
RUN rm -rf /output/aarch64/exe/*.rpm
COPY inbm-vision/node-agent /build/node-agent
COPY inbm-vision/vision-agent /build/vision-agent
ARG VERSION
ARG COMMIT
RUN mkdir -p /build/node-agent/fpm-template/usr/share/intel-manageability/ && \
    ( echo "Version: ${VERSION}" && echo "Commit: ${COMMIT}" ) >/build/node-agent/fpm-template/usr/share/intel-manageability/inbm-vision-node-version.txt 
RUN mkdir -p /build/vision-agent/fpm-template/usr/share/intel-manageability/ && \
    ( echo "Version: ${VERSION}" && echo "Commit: ${COMMIT}" ) >/build/vision-agent/fpm-template/usr/share/intel-manageability/inbm-vision-host-version.txt
WORKDIR /build
RUN cd node-agent && \
    rm -rf exe dist && \
    mkdir -p exe && \
    mkdir -p dist && \
    cp -r /input/exe/inbm-node exe/ && \
    ../packaging/build-agent-exe-py3.sh inbm-node rpm KMB agent && \
    mv -v dist/inbm-node*.rpm /output/aarch64
RUN cd vision-agent && \
    rm -rf exe dist && \
    mkdir -p exe && \
    mkdir -p dist && \
    cp -r /input/exe/inbm-vision exe/ && \
    ../packaging/build-agent-exe-py3.sh inbm-vision rpm KMB agent && \
    mv -v dist/inbm-vision*.rpm /output/aarch64

WORKDIR /build
COPY inbm-vision/Changelog.md /build/Changelog.md
RUN mkdir -p KMB
RUN mv -v /output/aarch64/* KMB
RUN rm -rf /output
RUN perl -pi -e 'chomp if eof' /build/version.txt && \
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
    ls -l && \
    for i in inbm-node-agent inbm-vision-agent; do \
      mv -v "$i"-"$VERSION"*.tar.gz "$i"-"$VERSION"-1.tar.gz ; \
    done
RUN mkdir -p /output && cp -r /build/KMB /output

