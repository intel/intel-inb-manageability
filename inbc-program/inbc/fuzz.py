from typing import List
import atheris
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../"))
#import sample1
with atheris.instrument_imports():
 
 from unittest import TestCase
 from inbc.inbc import Inbc

 #sys.path.append(os.path.join(os.path.dirname(__file__), "../"))
 from inbc.utility import search_keyword, is_vision_agent_installed
# from mock import Mock, patch
# import sys

payload = 'Status message FAILED'
#import inbc
@atheris.instrument_func
def search_keyword(payload: str, words: List[str]) -> bool:
    """Stop INBC after receiving expected response from vision-agent

    @param payload: MQTT message received from vision-agent
    @param words: expected keywords in the message
    @return: True if keyword found, False if keyword not found in message
    """
    for word in words:
        if payload.find(word) >= 0:
            return True
    return False

def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    data = fdp.ConsumeString(4000)
    output = search_keyword(payload, ["Configuration", "command", "FAILED"])
    #search_keyword == payload
    if output is False:
        return

    input_type = str(type(data))
    codepoints = [hex(ord(x)) for x in data]
    sys.stdout.write(f"Input was {input_type}: {data}\nCodepoints: {codepoints}")
    raise Exception ("try again")


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

