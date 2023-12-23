FROM debian:bookworm-slim as untar
COPY ../Intel-Manageability.preview.tar.gz /src/Intel-Manageability.preview.tar.gz
WORKDIR /src/
RUN tar zxvf Intel-Manageability.preview.tar.gz
RUN mkdir /mqtt-deb-extract && dpkg -X mqtt*.deb /mqtt-deb-extract

FROM eclipse-mosquitto as final
COPY --from=untar /mqtt-deb-extract /mqtt-deb
COPY mosquitto/mosquitto.conf /conf/mosquitto.conf
COPY /scripts/wait-for-certs.sh /wait-for-certs.sh
RUN chmod +x /wait-for-certs.sh
ENTRYPOINT ["/wait-for-certs.sh", "/docker-entrypoint.sh"]
CMD ["/usr/sbin/mosquitto", "-c", "/conf/mosquitto.conf"]
