# Copyright (c) 2024 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

include(`image.main.m4')

# base windows/wine build image
FROM registry.hub.docker.com/tobix/pywine:3.12 as base-windows

ENV DEBIAN_FRONTEND noninteractive

# install Microsoft Visual C++ Redistributable for Visual Studio 2017 dll files
# RUN set -x \
#    && rm -f "$W_TMP"/* \
#    && wget -P "$W_TMP" https://download.visualstudio.microsoft.com/download/pr/11687613/88b50ce70017bf10f2d56d60fcba6ab1/VC_redist.x86.exe \
#    && cabextract -q --directory="$W_TMP" "$W_TMP"/VC_redist.x86.exe \
#    && cabextract -q --directory="$W_TMP" "$W_TMP/a10" \
#    && cabextract -q --directory="$W_TMP" "$W_TMP/a11" \
#    && cd "$W_TMP" \
#    && rename 's/_/\-/g' *.dll \
#    && cp "$W_TMP"/*.dll "$W_SYSTEM_DLLS"/

RUN cd /opt/wineprefix/drive_c/Python \
    && echo 'wine '\''C:\Python\python.exe'\'' "$@"' > /usr/bin/python \
    && echo 'wine '\''C:\Python\Scripts\easy_install.exe'\'' "$@"' > /usr/bin/easy_install \
    && echo 'wine '\''C:\Python\Scripts\pip.exe'\'' "$@"' > /usr/bin/pip \
    && echo 'wine '\''C:\Python\Scripts\pyinstaller.exe'\'' "$@"' > /usr/bin/pyinstaller \
    && echo 'wine '\''C:\Python\Scripts\pyupdater.exe'\'' "$@"' > /usr/bin/pyupdater \
    && chmod a+x /usr/bin/python /usr/bin/easy_install /usr/bin/pip /usr/bin/pyinstaller /usr/bin/pyupdater


# put the src folder inside wine
RUN mkdir /src/ && ln -s /src /opt/wineprefix/drive_c/src
VOLUME /src/
WORKDIR /opt/wineprefix/drive_c/src/
RUN mkdir -p /opt/wineprefix/drive_c/tmp


RUN ln -sf /usr/bin/pip /usr/bin/pip3
RUN python -m pip install --upgrade pip
RUN pip3 install setuptools-rust
RUN pip3 install pywin32
RUN pip3 install wheel
COPY inbm-lib /src/inbm-lib
RUN pip3 install -e /src/inbm-lib

FROM base-windows as windows-cloudadapter-py3
COPY inbm/cloudadapter-agent/requirements.txt /src/cloudadapter-agent/requirements.txt
COPY inbm/cloudadapter-agent/test-requirements.txt /src/cloudadapter-agent/test-requirements.txt
WORKDIR /src/cloudadapter-agent
# RUN cp -r /src/inbm-lib/inbm_* /src/cloudadapter-agent/
RUN pip3 install --prefer-binary -r requirements.txt && \    
    pip3 uninstall -y chardet # license issue

COPY inbm/cloudadapter-agent /src/cloudadapter-agent
COPY inbm/packaging /src/packaging
RUN mkdir -p /output && \
    pip3 install -r requirements.txt
RUN pyinstaller inbm-cloudadapter-windows.spec && \
    cp -r ../cloudadapter-agent/dist/inbm-cloudadapter /output

FROM registry.hub.docker.com/library/golang:1.22-bookworm as inb-provision-certs-windows
COPY inbm/fpm/inb-provision-certs /inb-provision-certs
RUN cd /inb-provision-certs && GOOS=windows GOARCH=386 CGO_ENABLED=0 go build . && \
    rm -rf /output/ && mkdir /output && cp /inb-provision-certs/inb-provision-certs.exe /output/inb-provision-certs.exe

FROM registry.hub.docker.com/library/golang:1.22-bookworm as inb-provision-cloud-windows
COPY inbm/fpm/inb-provision-cloud /inb-provision-cloud
RUN cd /inb-provision-cloud && GOOS=windows GOARCH=386 CGO_ENABLED=0 go build . && \
    rm -rf /output/ && mkdir /output && cp /inb-provision-cloud/inb-provision-cloud.exe /output/inb-provision-cloud.exe

FROM registry.hub.docker.com/library/golang:1.22-bookworm as inb-provision-ota-cert-windows
COPY inbm/fpm/inb-provision-ota-cert /inb-provision-ota-cert
RUN cd /inb-provision-ota-cert && GOOS=windows GOARCH=386 CGO_ENABLED=0 go build . && \
    rm -rf /output/ && mkdir /output && cp /inb-provision-ota-cert/inb-provision-ota-cert.exe /output/inb-provision-ota-cert.exe

# output container
FROM registry.hub.docker.com/library/ubuntu:20.04 as output-windows
RUN apt-get update && apt-get install -y -q wget
COPY --from=windows-cloudadapter-py3 /output/ /windows-cloudadapter-py3
COPY --from=inb-provision-certs-windows /output /windows-inb-provision-certs
COPY --from=inb-provision-cloud-windows /output /windows-inb-provision-cloud
COPY --from=inb-provision-ota-cert-windows /output /windows-inb-provision-ota-cert
COPY --from=cloudadapter-py3 /output /cloudadapter
COPY --from=fpm /output /fpm
COPY inbm/packaging/windows-override /windows-override
RUN mkdir -p /output/windows 
COPY third-party-programs.txt /output/windows
WORKDIR /output/windows

# Copy our built Windows .exe files/directories to our bin directories
RUN \
    set -ex && \
    mkdir -p intel-manageability/inbm/usr/bin/ && \
    mkdir -p broker/usr/bin/ && \
    cp -vr /windows-cloudadapter-py3/inbm-cloudadapter/ intel-manageability/inbm/usr/bin/inbm-cloudadapter/ && \    
    cp -v /windows-inb-provision-certs/inb-provision-certs.exe broker/usr/bin/ && \
    cp -v /windows-inb-provision-cloud/inb-provision-cloud.exe broker/usr/bin/ && \
    cp -v /windows-inb-provision-ota-cert/inb-provision-ota-cert.exe broker/usr/bin/

# Extract files needed for Windows from our .debs for Linux
RUN \
    set -ex && \
    mkdir -p intel-manageability/inbm/usr/share/cloudadapter-agent/ && \
    mkdir -p intel-manageability/inbm/usr/share/intel-manageability/ && \
    mkdir -p broker/etc/public/mqtt-broker/ && \
    mkdir -p intel-manageability/inbm/var && \
    touch intel-manageability/inbm/var/manageability.log && \
    dpkg -X /cloudadapter/inbm-cloudadapter*.deb /cloudadapter-deb && \    
    cp -v /cloudadapter-deb/usr/share/cloudadapter-agent/config_schema.json intel-manageability/inbm/usr/share/cloudadapter-agent/ && \
    cp -rv /cloudadapter-deb/usr/share/cloudadapter-agent/thingsboard intel-manageability/inbm/usr/share/cloudadapter-agent/ && \
    cp -rv /cloudadapter-deb/usr/share/cloudadapter-agent/ucc intel-manageability/inbm/usr/share/cloudadapter-agent/ && \
    ls -lR /fpm/ && \
    dpkg -X /fpm/mqtt*.deb /mqtt-deb && \
    cp -rv /mqtt-deb/usr/share/intel-manageability/ intel-manageability/inbm/usr/share/intel-manageability/ && \
    cp -rv /mqtt-deb/etc/intel-manageability/public/mqtt-broker/acl.file broker/etc/public/mqtt-broker/

# Copy in our Windows-only files
RUN \
    cp -rv /windows-override/* intel-manageability/
