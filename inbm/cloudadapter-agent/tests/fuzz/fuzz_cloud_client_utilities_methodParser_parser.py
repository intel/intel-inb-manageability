import atheris
import sys

with atheris.instrument_imports():
    from cloudadapter.cloud.client.utilities import MethodParser

mp = MethodParser({
    "method": {
        "regex": r"methods\/([\w_-]+)",
        "group": 1
    },
    "args": {
        "path": "parent/child/item"
    }
})


@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    topic_data = fdp.ConsumeString(1000)
    payload_data = fdp.ConsumeString(5000)

    try:
        mp.parse(topic_data, payload_data)
    except ValueError:
        pass
    except Exception:
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
