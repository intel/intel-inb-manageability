# build x86 assets
include(`image.main.m4')

FROM ubuntu:20.04 as base-x86_64
include(`commands.base-setup.m4')

FROM base-x86_64 as output-ehl
COPY --from=output-main /output /output
RUN set -ex && \
    mkdir -p /build && \
    cd /build && \
    mkdir -p x86_64 && \
    cp /output/*.rpm x86_64 && \
    rm -rf /output && \
    mkdir -p EHL && \
    VERSION=$(echo x86_64/trtl-*EHL.rpm | perl -e ' while (<>) { s/^.*-(\d+\.\d+\.\d+).*$/\1/g; print; } ') && \
    mv -v x86_64/*EHL*.rpm EHL && \
    mv -v x86_64/yocto-provision*.rpm EHL && \
    mv -v x86_64/mqtt*.rpm EHL
COPY inbm/Changelog.md /build/EHL
RUN cd /build/EHL && \
      for file in *.rpm ; do \
        TAR="$(basename "$file" .rpm).tar" && \
        fpm -s rpm -t tar -p "$TAR" "$file"  && rm -fv "$file" && \
        tar --delete -f "$TAR" ./.scripts && \
        gzip -v "$TAR" && \
        rm -fv "$TAR" ; \
      done
COPY inbm/version.txt /build
RUN set -e && cd /build/EHL && \
    perl -pi -e 'chomp if eof' /build/version.txt && \
    VERSION=$(cat /build/version.txt) && \
    for i in inbm-cloudadapter-agent inbm-dispatcher-agent inbm-diagnostic-agent inbm-telemetry-agent inbm-configuration-agent inbc-program trtl; do \
        mv -v "$i"-"$VERSION"*.tar.gz "$i"-"$VERSION"-1.tar.gz || /bin/false ; \
    done
RUN mkdir -p /output && cp -r /build/EHL /output/EHL
