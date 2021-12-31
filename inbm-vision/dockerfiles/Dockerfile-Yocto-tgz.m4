include(`image.kmb.m4')

FROM registry.hub.docker.com/library/ubuntu:18.04 as output-yocto
COPY --from=output-kmb /output /kmb
RUN mkdir -p /output && \
    cp -rv \
    /kmb/* \
    /output

