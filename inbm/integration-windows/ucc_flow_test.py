#!/usr/bin/env python3

import paho.mqtt.client as mqtt
import time

ucc_broker = "localhost"
ucc_port = 4000
ucc_ca_file = '/intel-manageability/broker/etc/secret/cloudadapter-agent/ucc-ca.crt'
ucc_client_cert = '/intel-manageability/broker/etc/secret/cloudadapter-agent/ucc-client.crt'
ucc_client_key = '/intel-manageability/broker/etc/secret/cloudadapter-agent/ucc-client.key'

tc_broker = "localhost"
tc_port = 8883
tc_ca_file = "/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt"
tc_client_cert = (
    "/etc/intel-manageability/public/ucc-native-service/ucc-native-service.crt"
)
tc_client_key = (
    "/etc/intel-manageability/secret/ucc-native-service/ucc-native-service.key"
)


def on_message(client, userdata, message):
    userdata[message.topic] = message.payload.decode()


def setup_client(broker, port, ca_file, client_cert, client_key):
    client = mqtt.Client(client_id="test", userdata={})
    client.tls_set(ca_certs=ca_file, certfile=client_cert, keyfile=client_key)
    client.connect(broker, port)
    client.on_message = on_message
    return client


ucc_client = setup_client(
    ucc_broker, ucc_port, ucc_ca_file, ucc_client_cert, ucc_client_key
)
tc_client = setup_client(tc_broker, tc_port, tc_ca_file, tc_client_cert, tc_client_key)

ucc_received_messages = {}
ucc_client.user_data_set(ucc_received_messages)
ucc_client.loop_start()

tc_received_messages = {}
tc_client.user_data_set(tc_received_messages)
tc_client.loop_start()

TEST_PAYLOAD = '{"some": "arbitrary", "json": "string"}'

# Telemetry test
UCC_TEL_REQ = "uccctl/tel/req/123/12345678abcd"

ucc_client.subscribe(UCC_TEL_REQ)
tc_client.publish("manageability/telemetry", TEST_PAYLOAD)

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

ucc_client.subscribe(UCC_CMD_RES)
tc_client.subscribe(TC_CMD_REQ)

ucc_client.publish("uccctl/cmd/req/123/12345678abcd", TEST_PAYLOAD)

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
