import atheris
import sys

with atheris.instrument_imports():
    from cloudadapter.cloud.client.connections.mqtt_connection import MQTTConnection
    enable_loader_override = False

@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    user_data = fdp.ConsumeString(60)
    hostname_data = fdp.ConsumeString(60)
    port_data = fdp.ConsumeString(10)
    password_data = fdp.ConsumeString(60)

    try:
        MQTTConnection(username=user_data, hostname=hostname_data, port=port_data, password=password_data)
    except ValueError:
        pass
    except Exception:
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
