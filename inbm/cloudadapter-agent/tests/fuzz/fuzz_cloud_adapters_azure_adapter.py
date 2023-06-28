import atheris
import sys

with atheris.instrument_imports():
    from cloudadapter.cloud.adapters.azure_adapter import AzureAdapter
    from cloudadapter.exceptions import AdapterConfigureError
    enable_loader_override = False


@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    scope_data = fdp.ConsumeString(100)
    device_data = fdp.ConsumeString(100)
    sas_data = fdp.ConsumeString(1000)
    certs_data = fdp.ConsumeString(500)
    device_key_data = fdp.ConsumeString(500)

    try:
        config = {
            "scope_id": scope_data,
            "device_id": device_data,
            "device_sas_key": sas_data,
            "device_certs": certs_data,
            "device_key": device_key_data
        }
        azure_adapter = AzureAdapter(config)
        azure_adapter.configure(config)
    except AdapterConfigureError:
        pass
    except Exception:
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
