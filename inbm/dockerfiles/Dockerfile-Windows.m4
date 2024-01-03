include(`image.main.m4')

# base windows/wine build image
FROM registry.hub.docker.com/library/ubuntu:22.04 as base-windows

ENV DEBIAN_FRONTEND noninteractive

ARG WINE_VERSION=winehq-stable
ARG PYTHON_VERSION=3.11.5
ARG PYINSTALLER_VERSION=5.13.1

# we need wine for this all to work, so we'll use the PPA
RUN set -x \
    && dpkg --add-architecture i386 \
    && apt-get update -qy \
    && apt-get install --no-install-recommends -qfy gpg-agent apt-transport-https software-properties-common wget rename \
    && wget -nv https://dl.winehq.org/wine-builds/winehq.key \
    && apt-key add winehq.key \
    && add-apt-repository 'https://dl.winehq.org/wine-builds/ubuntu/' \
    && apt-get update -qy \
    && apt-get install --no-install-recommends -qfy $WINE_VERSION winbind cabextract \
    && apt-get clean \
    && wget -nv https://raw.githubusercontent.com/Winetricks/winetricks/master/src/winetricks \
    && chmod +x winetricks \
    && mv winetricks /usr/local/bin

# wine settings
ENV WINEARCH win32
ENV WINEDEBUG fixme-all
ENV WINEPREFIX /wine

# PYPI repository location
ENV PYPI_URL=https://pypi.python.org/
# PYPI index location
ENV PYPI_INDEX_URL=https://pypi.python.org/simple

# install python in wine, using the msi packages to install, extracting
# the files directly, since installing isn't running correctly.
RUN set -x \
    && winetricks win10 \
    && for msifile in core dev exe lib path pip tcltk tools; do \
        wget -nv "https://www.python.org/ftp/python/$PYTHON_VERSION/win32/${msifile}.msi"; \
        wine msiexec /i "${msifile}.msi" /qb TARGETDIR=C:/Python3; \
        rm ${msifile}.msi; \
    done \
    && cd /wine/drive_c/Python3 \
    && echo 'wine '\''C:\Python3\python.exe'\'' "$@"' > /usr/bin/python \
    && echo 'wine '\''C:\Python3\Scripts\easy_install.exe'\'' "$@"' > /usr/bin/easy_install \
    && echo 'wine '\''C:\Python3\Scripts\pip.exe'\'' "$@"' > /usr/bin/pip \
    && echo 'wine '\''C:\Python3\Scripts\pyinstaller.exe'\'' "$@"' > /usr/bin/pyinstaller \
    && echo 'wine '\''C:\Python3\Scripts\pyupdater.exe'\'' "$@"' > /usr/bin/pyupdater \
    && echo 'assoc .py=PythonScript' | wine cmd \
    && echo 'ftype PythonScript=c:\Python3\python.exe "%1" %*' | wine cmd \
    && while pgrep wineserver >/dev/null; do echo "Waiting for wineserver"; sleep 1; done \
    && chmod +x /usr/bin/python /usr/bin/easy_install /usr/bin/pip /usr/bin/pyinstaller /usr/bin/pyupdater \
    && (pip install -U pip || true) \
    && rm -rf /tmp/.wine-*

ENV W_DRIVE_C=/wine/drive_c
ENV W_WINDIR_UNIX="$W_DRIVE_C/windows"
ENV W_SYSTEM_DLLS="$W_WINDIR_UNIX/system32"
ENV W_TMP="$W_DRIVE_C/windows/temp/_$0"

# install Microsoft Visual C++ Redistributable for Visual Studio 2017 dll files
RUN set -x \
    && rm -f "$W_TMP"/* \
    && wget -P "$W_TMP" https://download.visualstudio.microsoft.com/download/pr/11687613/88b50ce70017bf10f2d56d60fcba6ab1/VC_redist.x86.exe \
    && cabextract -q --directory="$W_TMP" "$W_TMP"/VC_redist.x86.exe \
    && cabextract -q --directory="$W_TMP" "$W_TMP/a10" \
    && cabextract -q --directory="$W_TMP" "$W_TMP/a11" \
    && cd "$W_TMP" \
    && rename 's/_/\-/g' *.dll \
    && cp "$W_TMP"/*.dll "$W_SYSTEM_DLLS"/

# install pyinstaller
RUN /usr/bin/pip install pyinstaller==$PYINSTALLER_VERSION

# put the src folder inside wine
RUN mkdir /src/ && ln -s /src /wine/drive_c/src
VOLUME /src/
WORKDIR /wine/drive_c/src/
RUN mkdir -p /wine/drive_c/tmp


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
    wine ../cloudadapter-agent/dist/inbm-cloudadapter/inbm-cloudadapter.exe install && \
    cp -r ../cloudadapter-agent/dist/inbm-cloudadapter /output

FROM registry.hub.docker.com/library/golang:1.20-bookworm as inb-provision-certs-windows
COPY inbm/fpm/inb-provision-certs /inb-provision-certs
RUN cd /inb-provision-certs && GOOS=windows GOARCH=386 CGO_ENABLED=0 go build . && \
    rm -rf /output/ && mkdir /output && cp /inb-provision-certs/inb-provision-certs.exe /output/inb-provision-certs.exe

FROM registry.hub.docker.com/library/golang:1.20-bookworm as inb-provision-cloud-windows
COPY inbm/fpm/inb-provision-cloud /inb-provision-cloud
RUN cd /inb-provision-cloud && GOOS=windows GOARCH=386 CGO_ENABLED=0 go build . && \
    rm -rf /output/ && mkdir /output && cp /inb-provision-cloud/inb-provision-cloud.exe /output/inb-provision-cloud.exe

FROM registry.hub.docker.com/library/golang:1.20-bookworm as inb-provision-ota-cert-windows
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
