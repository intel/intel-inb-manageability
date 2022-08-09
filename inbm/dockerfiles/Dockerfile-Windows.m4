include(`image.main.m4')

# base windows/wine build image
FROM registry.hub.docker.com/cdrx/pyinstaller-windows:python3 as base-windows
# The following RUN command is derived from cdrx/docker-pyinstaller(https://github.com/cdrx/docker-pyinstaller/blob/master/LICENSE) 
RUN set -x \
    && rm -f "$W_TMP"/* \
    && wget -P "$W_TMP" https://aka.ms/vs/16/release/vc_redist.x64.exe \
    && cabextract -q --directory="$W_TMP" "$W_TMP"/vc_redist.x64.exe \
    && cabextract -q --directory="$W_TMP" "$W_TMP/a10" \
    && cabextract -q --directory="$W_TMP" "$W_TMP/a11" \
    && cd "$W_TMP" \
    && rename 's/_/\-/g' *.dll \
    && cp "$W_TMP"/*.dll "$W_SYSTEM64_DLLS"/
RUN ln -sf /usr/bin/pip /usr/bin/pip3
RUN python -m pip install --upgrade pip
RUN pip3 install setuptools-rust
RUN pip3 install pywin32
COPY inbm-lib /src/inbm-lib-editable
RUN pip3 install -e /src/inbm-lib-editable

FROM base-windows as windows-dispatcher-py3
COPY inbm/dispatcher-agent/requirements.txt /src/dispatcher-agent/requirements.txt
COPY inbm/dispatcher-agent/test-requirements.txt /src/dispatcher-agent/test-requirements.txt
WORKDIR /src/dispatcher-agent
RUN pip3 install -r requirements.txt && \
    pip3 install -r test-requirements.txt

COPY inbm/dispatcher-agent /src/dispatcher-agent
COPY inbm/packaging /src/packaging
RUN mkdir -p /output && \
    ../packaging/run-pyinstaller-py3.sh inbm-dispatcher-agent dispatcher && \
    cp -r ../dispatcher-agent/dist/"dispatcher.exe" /output

FROM base-windows as windows-cloudadapter-py3
COPY inbm/cloudadapter-agent/requirements.txt /src/cloudadapter-agent/requirements.txt
COPY inbm/cloudadapter-agent/test-requirements.txt /src/cloudadapter-agent/test-requirements.txt
WORKDIR /src/cloudadapter-agent
RUN pip3 install -r requirements.txt && \
    pip3 uninstall -y chardet # license issue

COPY inbm/cloudadapter-agent /src/cloudadapter-agent
COPY inbm/packaging /src/packaging
RUN mkdir -p /output && \
    ../packaging/run-pyinstaller-py3.sh cloudadapter-agent cloudadapter && \
    cp -r ../cloudadapter-agent/dist/"cloudadapter.exe" /output

FROM base-windows as windows-telemetry-py3
COPY inbm/telemetry-agent/requirements.txt /src/telemetry-agent/requirements.txt
COPY inbm/telemetry-agent/test-requirements.txt /src/telemetry-agent/test-requirements.txt
WORKDIR /src/telemetry-agent
RUN pip3 install -r requirements.txt && \
    pip3 uninstall -y chardet # license issue
COPY inbm/telemetry-agent /src/telemetry-agent
COPY inbm/packaging /src/packaging
RUN mkdir -p /output && \
    ../packaging/run-pyinstaller-py3.sh telemetry-agent telemetry && \
    cp -r ../telemetry-agent/dist/"telemetry.exe" /output

FROM base-windows as windows-configuration-py3
COPY inbm/configuration-agent/requirements.txt /src/configuration-agent/requirements.txt
COPY inbm/configuration-agent/test-requirements.txt /src/configuration-agent/test-requirements.txt
WORKDIR /src/configuration-agent
RUN pip3 install -r requirements.txt
COPY inbm/configuration-agent /src/configuration-agent
COPY inbm/packaging /src/packaging
RUN mkdir -p /output && \
    ../packaging/run-pyinstaller-py3.sh configuration-agent configuration && \
    cp -r ../configuration-agent/dist/"configuration.exe" /output

FROM base-windows as windows-diagnostic-py3
COPY inbm/diagnostic-agent/requirements.txt /src/diagnostic-agent/requirements.txt
COPY inbm/diagnostic-agent/test-requirements.txt /src/diagnostic-agent/test-requirements.txt
WORKDIR /src/diagnostic-agent
RUN pip3 install -r requirements.txt
COPY inbm/diagnostic-agent /src/diagnostic-agent
COPY inbm/packaging /src/packaging
RUN mkdir -p /output && \
    ../packaging/run-pyinstaller-py3.sh diagnostic-agent diagnostic && \
    cp -r ../diagnostic-agent/dist/"diagnostic.exe" /output

FROM registry.hub.docker.com/library/golang:1.18-buster as inb-provision-certs-windows
COPY inbm/fpm/inb-provision-certs /inb-provision-certs
RUN cd /inb-provision-certs && GOOS=windows GOARCH=amd64 go build . && \
    rm -rf /output/ && mkdir /output && cp /inb-provision-certs/inb-provision-certs.exe /output/inb-provision-certs.exe

FROM registry.hub.docker.com/library/golang:1.18-buster as inb-provision-cloud-windows
COPY inbm/fpm/inb-provision-cloud /inb-provision-cloud
RUN cd /inb-provision-cloud && GOOS=windows GOARCH=amd64 go build . && \
    rm -rf /output/ && mkdir /output && cp /inb-provision-cloud/inb-provision-cloud.exe /output/inb-provision-cloud.exe

FROM registry.hub.docker.com/library/golang:1.18-buster as inb-provision-ota-cert
COPY inbm/fpm/inb-provision-ota-cert /inb-provision-ota-cert
RUN cd /inb-provision-ota-cert && GOOS=windows GOARCH=amd64 go build . && \
    rm -rf /output/ && mkdir /output && cp /inb-provision-ota-cert/inb-provision-ota-cert.exe /output/inb-provision-ota-cert.exe


FROM base-windows as windows-3rdparty
RUN mkdir -p /output && \
    cd /output && \
    wget https://slproweb.com/download/Win64OpenSSL_Light-1_1_1k.msi && \
    wget https://mosquitto.org/files/binary/win64/mosquitto-1.6.9-install-windows-x64.exe && \
    wget https://aka.ms/vs/16/release/vc_redist.x64.exe

# output container
FROM registry.hub.docker.com/library/ubuntu:20.04 as output-windows
COPY --from=windows-cloudadapter-py3 /output/ /windows-cloudadapter-py3
COPY --from=windows-telemetry-py3 /output/ /windows-telemetry-py3
COPY --from=windows-dispatcher-py3 /output/ /windows-dispatcher-py3
COPY --from=windows-configuration-py3 /output/ /windows-configuration-py3
COPY --from=windows-diagnostic-py3 /output/ /windows-diagnostic-py3
COPY --from=windows-3rdparty /output/ /windows-3rdparty
COPY --from=inb-provision-certs-windows /output /windows-inb-provision-certs
COPY --from=inb-provision-cloud-windows /output /windows-inb-provision-cloud
COPY --from=inb-provision-certs-windows /output /windows-inb-provision-ota-cert
COPY --from=output-main /output /output-main
COPY inbm/packaging/windows-override /windows-override
RUN mkdir -p /output/windows 
WORKDIR /output/windows
COPY third-party-programs.txt /output/windows
RUN \
    set -ex && \
    cp -rv \
      /windows-cloudadapter-py3/* \
      /windows-telemetry-py3/* \
      /windows-dispatcher-py3/* \
      /windows-configuration-py3/* \
      /windows-diagnostic-py3/* \
      /windows-3rdparty/* \
      /windows-inb-provision-certs/* \
      /windows-inb-provision-cloud/* \
      /windows-inb-provision-ota-cert/* \
      /output/windows && \
    mkdir -p intel-manageability/inbm && \
    mkdir -p intel-manageability/broker && \
    ( for i in dispatcher cloudadapter telemetry mqtt configuration diagnostic ; do dpkg -x /output-main/$i*.deb intel-manageability/inbm ; done ) && \
    dpkg -x /output-main/mqtt*.deb intel-manageability/broker && \
    cd intel-manageability/inbm && \
    rm -rf etc/apparmor.d && \
    rm -rf usr/share/doc && \
    rm -rf usr/systemd && \
    rm -rf etc/systemd && \
    for i in cloudadapter dispatcher diagnostic configuration telemetry inb-provision-certs inb-provision-cloud inb-provision-ota-cert; do \
      rm usr/bin/$i && mv ../../$i.exe usr/bin ; \
    done && \
    for i in etc ; do \
      mv $i/intel-manageability/* $i && rm -rf $i/intel-manageability ; \
    done && \
    mv usr/bin bin && rm -rf usr/bin && \
    mkdir -p cache && \
    rm -rf var/cache && \
    cp -r /windows-override/* ../
