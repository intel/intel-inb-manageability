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
    data = fdp.ConsumeString(4000)

    try:
        mp.parse(data, "payload")
    except ValueError:
        pass

    input_type = str(type(data))
    codepoints = [hex(ord(x)) for x in data]
    sys.stdout.write(f"Input was {input_type}: {data}\nCodepoints: {codepoints}")
    raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
