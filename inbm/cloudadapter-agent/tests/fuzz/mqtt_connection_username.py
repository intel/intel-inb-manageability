import atheris
import sys

from cloudadapter.exceptions import ConnectError, DisconnectError, PublishError, AuthenticationError
with atheris.instrument_imports():
    from cloudadapter.cloud.client.connections.mqtt_connection import MQTTConnection


@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    data = fdp.ConsumeString(2000)

    try:
        MQTTConnection(username="user", hostname=data, port="8883")
    except Exception:
        return

    input_type = str(type(data))
    codebytes = data.decode('utf8', 'surrogateescape')
    sys.stdout.write(f"Input was {input_type}: {codebytes}\n")
    #raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
