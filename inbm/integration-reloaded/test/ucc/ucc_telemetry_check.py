import json
import os
import random
import string
import ssl
import time
import sys
import paho.mqtt.client as mqtt
import functools
import queue
from typing import Any, Dict


def validate_data(data: Dict[str, Any], random_payload: str) -> bool:
    """
    Validate the data received from the MQTT message. It should be in the format
    {"ts": "12345", "values": {"telemetry": "..."}}.

    :param data: The data received from the MQTT message as a dictionary.
    :return: True if the data is valid, False otherwise.
    """
    if "ts" not in data:
        print("Error: 'ts' field not found\n")
        return False

    if "values" not in data:
        print("Error: 'values' field not found\n")
        return False

    if "telemetry" not in data["values"]:
        print("Error: 'telemetry' field not found in 'values'\n")
        return False

    valuesTelemetry = data["values"]["telemetry"]
    expectedValuesTelemetry = random_payload

    if not isinstance(valuesTelemetry, str):
        print("Error: 'telemetry' is not of type string\n")
        return False

    if valuesTelemetry != expectedValuesTelemetry:
        print("Error: values/telemetry value in JSON is not as expected\n")
        print("Expected: " + expectedValuesTelemetry + "\n")
        print("Actual: " + valuesTelemetry + "\n")
        return False

    return True


def on_ucc_message(
    message_queue: queue.Queue,
    random_payload: str,
    client: mqtt.Client,
    userdata: Any,
    message: mqtt.MQTTMessage,
) -> None:
    """
    Callback function for when a message is received from the MQTT broker.
    Verify the message is what we're expecting and then flush stdout and
    force an exit with success (0) or failure (1).

    :param client: The MQTT client instance.
    :param userdata: User-defined data passed to the callback.
    :param message: The MQTT message received.
    """
    print(
        "(from UCC broker)"
        + "\nReceived: "
        + message.payload.decode("utf-8")
        + "\nTopic: "
        + message.topic
        + "\n"
    )

    data = json.loads(message.payload.decode("utf-8"))

    if not validate_data(data, random_payload):
        message_queue.put("failure")
    else:
        message_queue.put("success")


def main() -> None:
    """
    Set up the MQTT clients and publish the telemetry test message. Allow
    message handler to pass or fail the test if message is received, otherwise
    timeout with failure (exit code 1).
    """
    ucc_client = mqtt.Client(client_id="testing-subscribe")

    # random payload to ensure the string is really being passed through all the layers
    random_payload = "".join(random.choices(string.ascii_letters + string.digits, k=10))

    # create a callback that knows what random payload we chose
    message_queue: queue.Queue[str] = queue.Queue()
    ucc_client.on_message = functools.partial(
        on_ucc_message, message_queue, random_payload
    )

    ucc_client.tls_set(
        ca_certs="/etc/ucc_mosquitto/certs/ca.crt",
        certfile="/etc/ucc_mosquitto/certs/client.crt",
        keyfile="/etc/ucc_mosquitto/certs/client.key",
        tls_version=ssl.PROTOCOL_TLSv1_2,
    )
    ucc_client.connect("localhost", 4000, 60)
    ucc_client.subscribe("TopicTelemetryInfo/12345678abcd")
    ucc_client.loop_start()

    tc_client = mqtt.Client(client_id="testing-publish")
    tc_client.tls_set(
        ca_certs="/etc/intel-manageability/public/mqtt-ca/mqtt-ca.crt",
        certfile="/etc/intel-manageability/public/ucc-native-service/ucc-native-service.crt",
        keyfile="/etc/intel-manageability/secret/ucc-native-service/ucc-native-service.key",
        tls_version=ssl.PROTOCOL_TLSv1_2,
    )
    tc_client.connect("localhost", 8883, 60)
    tc_client.loop_start()

    tc_client.publish("manageability/telemetry", random_payload, qos=0)

    timeout = 5  # 5 seconds timeout
    try:
        result = message_queue.get(timeout=timeout)
        if result == "success":
            print("Correct format!\n")
            sys.exit(0)
        else:
            print("Error: incorrect format.\n")
            sys.exit(1)
    except queue.Empty:
        print("Timeout -- no response.\n")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Exception occurred: " + str(e) + "\n")
        sys.exit(1)
