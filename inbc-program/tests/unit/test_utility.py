from unittest import TestCase
from inbc.utility import search_keyword


class TestUtility(TestCase):

    def test_search_keyword_true(self):
        payload = 'Status message FAILED'
        output = search_keyword(payload, ["Configuration", "command", "FAILED"])
        assert output ==  True

    def test_search_keyword_false(self):
        payload = 'Status message SUCCESSFUL'
        output = search_keyword(payload, ["Commands"])
        assert output ==  False
