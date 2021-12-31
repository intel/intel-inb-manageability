from unittest import TestCase

from inbm_lib import wmi

WMIC_OUTPUT_1 = """Manufacturer    

Intel Corp.

"""
WMIC_PARSED_1 = {"Manufacturer": "Intel Corp."}

WMIC_OUTPUT_2 = """Date
500

"""
WMIC_PARSED_2 = {"Date": "500"}


class TestLoggingPath(TestCase):
    def test_parse_wmi_output_1(self) -> None:
        self.assertEqual(WMIC_PARSED_1, wmi.parse_wmic_output(WMIC_OUTPUT_1))

    def test_parse_wmi_output_2(self) -> None:
        self.assertEqual(WMIC_PARSED_2, wmi.parse_wmic_output(WMIC_OUTPUT_2))
