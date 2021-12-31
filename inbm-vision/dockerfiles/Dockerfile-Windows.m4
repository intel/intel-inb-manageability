include(`image.main.m4')

# base windows/wine build image
FROM registry.hub.docker.com/cdrx/pyinstaller-windows:python3 as base-windows
RUN ln -sf /usr/bin/pip /usr/bin/pip3
RUN pip3 install pywin32
COPY inbm-lib /src/inbm-lib
RUN pip3 install -e /src/inbm-lib

FROM base-windows as windows-vision-py3
COPY inbm-vision/vision-agent/requirements.txt /src/vision-agent/requirements.txt
COPY inbm-vision/vision-agent/test-requirements.txt /src/vision-agent/test-requirements.txt
WORKDIR /src/vision-agent
RUN pip3 install -r requirements.txt && \
    pip3 install -r test-requirements.txt
COPY inbm-vision/vision-agent /src/vision-agent
COPY inbm-vision/packaging /src/packaging
RUN mkdir -p /output && \
    ../packaging/run-pyinstaller-py3.sh vision-agent vision && \
    cp -r ../vision-agent/dist/"vision.exe" /output

FROM base-windows as windows-node-py3
COPY inbm-vision/node-agent/requirements.txt /src/node-agent/requirements.txt
COPY inbm-vision/node-agent/test-requirements.txt /src/node-agent/test-requirements.txt
WORKDIR /src/node-agent
RUN pip3 install -r requirements.txt && \
    pip3 install -r test-requirements.txt
COPY inbm-vision/node-agent /src/node-agent
COPY inbm-vision/packaging /src/packaging
RUN mkdir -p /output && \
    ../packaging/run-pyinstaller-py3.sh node-agent node && \
    cp -r ../node-agent/dist/"node.exe" /output

FROM base-windows as windows-inbc-py3
COPY inbc-program/requirements.txt /src/inbc-program/requirements.txt
COPY inbc-program/test-requirements.txt /src/inbc-program/test-requirements.txt
WORKDIR /src/inbc-program
RUN pip3 install -r requirements.txt && \
    pip3 install -r test-requirements.txt
COPY inbc-program /src/inbc-program
COPY inbm-vision/packaging /src/packaging
RUN mkdir -p /output && \
    ../packaging/run-pyinstaller-py3.sh inbc-program inbc && \
    cp -r ../inbc-program/dist/"inbc.exe" /output

# output container
FROM registry.hub.docker.com/library/ubuntu:18.04 as output-windows
COPY --from=windows-node-py3 /output/ /windows-node-py3
COPY --from=windows-vision-py3 /output/ /windows-vision-py3
COPY --from=windows-inbc-py3 /output/ /windows-inbc-py3
COPY --from=output /output /output
COPY inbm-vision/packaging/windows-override /windows-override
RUN mkdir -p /output/windows-inbm-vision 
WORKDIR /output/windows-inbm-vision
RUN \
    set -ex && \
    cp -rv \
      /windows-node-py3/* \
      /windows-vision-py3/* \
      /windows-inbc-py3/* \
      /output/windows-inbm-vision && \
    mkdir -p intel-manageability/inbm-vision && \
    ( for i in vision inbm-node inbc; do dpkg -x /output/$i*.deb intel-manageability/inbm-vision ; done ) && \
    cd intel-manageability/inbm-vision && \
    rm -rf etc/apparmor.d && \
    rm -rf usr/share/doc && \
    rm -rf usr/systemd && \
    rm -rf etc/systemd && \
    for i in vision inbm-node inbc; do \
      rm usr/bin/$i && mv ../../$i.exe usr/bin ; \
    done && \
    for i in etc ; do \
      mv $i/intel-manageability/* $i && rm -rf $i/intel-manageability ; \
    done && \
    mv usr/bin bin && rm -rf usr/bin && \
    mkdir -p cache && \
    rm -rf var/cache && \
    cp -r /windows-override/* ../
