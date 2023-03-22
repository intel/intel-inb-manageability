import atheris

with atheris.instrument_imports():
    from cloudadapter.cloud.client.connections.mqtt_connection import MQTTConnection
    from cloudadapter.exceptions import ConnectError, DisconnectError, PublishError, AuthenticationError
    import sys

def CustomMutator(data, max_size, seed):
    try:
        MQTTConnection(username="user", hostname=data, port="8883")
        data = atheris.Mutate(data, max_size)
    except Exception:
        return MQTTConnection(username="user", hostname=data, port="8883")
}

@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    data = fdp.ConsumeString(4000)

    try:
        MQTTConnection(username="user", hostname=data, port="8883")
    except Exception:
        return

    input_type = str(type(data))
    #codepoints = [hex(ord(x)) for x in data]
    sys.stdout.write(f"Input was {input_type}: {data}Codepoints: {data}\n")
    #raise


def main():
    atheris.Setup(sys.argv, TestOneInput, custom_mutator=CustomMutator)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
