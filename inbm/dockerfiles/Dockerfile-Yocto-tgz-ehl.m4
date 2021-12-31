include(`image.ehl.m4')

FROM registry.hub.docker.com/library/ubuntu:18.04 as output-yocto
COPY --from=output-ehl /output /ehl
RUN mkdir -p /output && \
    cp -rv \
    /ehl/* \
    /output

