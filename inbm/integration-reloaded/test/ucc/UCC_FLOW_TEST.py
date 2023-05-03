#!/usr/bin/env python3

import paho.mqtt.client as mqtt
import time
from typing import Dict
import os

if os.name == "nt":
    ucc_broker = "localhost"
    ucc_port = 4000
    ucc_ca_file = "/intel-manageability/broker/etc/secret/cloudadapter-agent/ucc-ca.crt"
    ucc_client_cert = (
        "/intel-manageability/broker/etc/secret/cloudadapter-agent/ucc-client.crt"
    )
    ucc_client_key = (
        "/intel-manageability/broker/etc/secret/cloudadapter-agent/ucc-client.key"
    )

    tc_broker = "localhost"
    tc_port = 8883
    tc_ca_file = "/intel-manageability/broker/etc/public/mqtt-ca/mqtt-ca.crt"
    tc_client_cert = "/intel-manageability/broker/etc/public/ucc-native-service/ucc-native-service.crt"
    tc_client_key = "/intel-manageability/broker/etc/secret/ucc-native-service/ucc-native-service.key"
elif os.name == "posix":
    ucc_broker = "localhost"
    ucc_port = 4000
    ucc_ca_file = "/etc/ucc_mosquitto/certs/ca.crt"
    ucc_client_cert = "/etc/ucc_mosquitto/certs/client.crt"
    ucc_client_key = "/etc/ucc_mosquitto/certs/client.key"

    tc_broker = "localhost"
    tc_port = 8883
    tc_ca_file = "/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt"
    tc_client_cert = (
        "/etc/intel-manageability/public/ucc-native-service/ucc-native-service.crt"
    )
    tc_client_key = (
        "/etc/intel-manageability/secret/ucc-native-service/ucc-native-service.key"
    )
else:
    print("Unsupported platform.")
    exit(1)


def setup_client(
    broker_name, broker, port, ca_file, client_cert, client_key, client_id
):
    def on_message(client, userdata, message):
        print(
            f"[{broker_name}] Received message on topic {message.topic}: {message.payload.decode()}"
        )
        userdata[message.topic] = message.payload.decode()

    def on_disconnect(client, userdata, rc):
        print(f"[{broker_name}] Disconnected with result code {rc}")

    client = mqtt.Client(client_id=client_id)
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    client.tls_set(ca_certs=ca_file, certfile=client_cert, keyfile=client_key)
    client.connect(broker, port)
    return client


ucc_client = setup_client(
    "UCC", ucc_broker, ucc_port, ucc_ca_file, ucc_client_cert, ucc_client_key, "testucc"
)
tc_client = setup_client(
    "TC", tc_broker, tc_port, tc_ca_file, tc_client_cert, tc_client_key, "testtc"
)

ucc_received_messages: Dict[str, str] = {}
ucc_client.user_data_set(ucc_received_messages)
ucc_client.loop_start()

# Subscribe to ucc_client and check for errors
result, _ = ucc_client.subscribe("#")
if result != mqtt.MQTT_ERR_SUCCESS:
    print(f"Error subscribing to ucc_client: {mqtt.error_string(result)}")
    exit(1)

tc_received_messages: Dict[str, str] = {}
tc_client.user_data_set(tc_received_messages)
tc_client.loop_start()

# Subscribe to tc_client and check for errors
result, _ = tc_client.subscribe("#")
if result != mqtt.MQTT_ERR_SUCCESS:
    print(f"Error subscribing to tc_client: {mqtt.error_string(result)}")
    exit(1)

TEST_PAYLOAD = '{"some": "arbitrary", "json": "string"}'

# Telemetry test
UCC_TEL_REQ = "uccctl/tel/req/123/12345678abcd"

# not necessary due to subscribing to # above
# ucc_client.subscribe("UCC_TEL_REQ")

# Publish to tc_client and check for errors
result, _ = tc_client.publish("manageability/telemetry", TEST_PAYLOAD)
if result != mqtt.MQTT_ERR_SUCCESS:
    print(f"Error publishing to tc_client: {mqtt.error_string(result)}")
    exit(1)

time.sleep(2)

if UCC_TEL_REQ not in ucc_received_messages:
    print("UCC telemetry test failed: no response received")
    exit(1)

response = ucc_received_messages[UCC_TEL_REQ]

expected = TEST_PAYLOAD
if response != expected:
    print(f"UCC telemetry test failed: expected {expected}, got {response}")
    exit(1)

print("UCC telemetry test passed")

# Command test
UCC_CMD_RES = "uccctl/cmd/res/123/12345678abcd"
TC_CMD_REQ = "manageability/request/command"

# not necessary due to subscribing to # above
# ucc_client.subscribe(UCC_CMD_RES)
# tc_client.subscribe(TC_CMD_REQ)

# Publish to ucc_client and check for errors
result, _ = ucc_client.publish("uccctl/cmd/req/123/12345678abcd", TEST_PAYLOAD)
if result != mqtt.MQTT_ERR_SUCCESS:
    print(f"Error publishing to ucc_client: {mqtt.error_string(result)}")
    exit(1)

time.sleep(2)

if TC_CMD_REQ not in tc_received_messages or UCC_CMD_RES not in ucc_received_messages:
    print("UCC command test failed: no response received")
    exit(1)

tc_response = tc_received_messages[TC_CMD_REQ]
ucc_response = ucc_received_messages[UCC_CMD_RES]

expected_tc_response = TEST_PAYLOAD
expected_ucc_response = "OK"
if tc_response != expected_tc_response or ucc_response != expected_ucc_response:
    print(
        f"UCC command test failed: expected {expected_tc_response} and {expected_ucc_response}"
    )
    print(f"got: {tc_response} and {ucc_response}")
    exit(1)

print("UCC command test passed")
print("UCC flow test passed")

ucc_client.loop_stop()
tc_client.loop_stop()
ucc_client.disconnect()
tc_client.disconnect()

exit(0)
