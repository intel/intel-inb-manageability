FROM eclipse-mosquitto
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
COPY wait-for-certs.sh /wait-for-certs.sh
RUN chmod +x /wait-for-certs.sh
ENTRYPOINT ["/wait-for-certs.sh", "mosquitto"]