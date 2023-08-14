FROM ubuntu:22.04 as untar
COPY Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz
WORKDIR /src
RUN tar zxvf Intel-Manageability.preview.tar.gz

FROM ubuntu:22.04 as final
ARG http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY
ENV http_proxy=$http_proxy https_proxy=$https_proxy no_proxy=$no_proxy HTTP_PROXY=$HTTP_PROXY HTTPS_PROXY=$HTTPS_PROXY NO_PROXY=$NO_PROXY
RUN mkdir /deb
COPY --from=untar /src/mqtt*.deb /deb
RUN mkdir /mqtt-deb && dpkg -X /deb/mqtt*.deb /mqtt-deb
RUN apt-get update && apt-get install -y openssl
COPY certgen/generate-certs.sh /generate-certs.sh
RUN chmod +x /generate-certs.sh
CMD ["/bin/bash", "/generate-certs.sh"]