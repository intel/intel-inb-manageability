from unittest import TestCase
from inbc.utility import search_keyword


class TestUtility(TestCase):

    def test_search_keyword_true(self) -> None:
        payload = 'Status message FAILED'
        output = search_keyword(payload, ["Configuration", "command", "FAILED"])
        self.assertEqual(output, True)

    def test_search_keyword_false(self) -> None:
        payload = 'Status message SUCCESSFUL'
        output = search_keyword(payload, ["Commands"])
        self.assertEqual(output, False)
