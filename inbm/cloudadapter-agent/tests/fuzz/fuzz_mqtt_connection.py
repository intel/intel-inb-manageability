import atheris
import sys

with atheris.instrument_imports():
    from cloudadapter.cloud.client.connections.mqtt_connection import MQTTConnection
    from cloudadapter.exceptions import ConnectError
    from cloudadapter.cloud.client.utilities import ProxyConfig, TLSConfig
    enable_loader_override = False


@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    user_data = fdp.ConsumeString(60)
    hostname_data = fdp.ConsumeString(60)
    port_data = fdp.ConsumeUInt(65535)
    password_data = fdp.ConsumeString(60)
    client_id_data = fdp.ConsumeString(40)
    cert_data = fdp.ConsumeString(2500)

    tls = TLSConfig(cert_data, cert_data, cert_data)
    proxy = ProxyConfig(hostname_data, port_data)

    try:
        MQTTConnection(username=user_data, hostname=hostname_data, port=port_data,
                       client_id=client_id_data, password=password_data, tls_config=tls, proxy_config=proxy)
    except (OSError, ValueError, ConnectError):
        pass
    except Exception:
        raise


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
