from unittest import TestCase
from inbc.utility import search_keyword, is_vision_agent_installed
from mock import Mock, patch
from os import path


class TestUtility(TestCase):

    def test_search_keyword_true(self):
        payload = 'Status message FAILED'
        output = search_keyword(payload, ["Configuration", "command", "FAILED"])
        self.assertEquals(output, True)

    def test_search_keyword_false(self):
        payload = 'Status message SUCCESSFUL'
        output = search_keyword(payload, ["Commands"])
        self.assertEquals(output, False)

    @patch('os.path.exists', return_value = True)
    def test_vision_agent_installed_true(self, mock):
        output = is_vision_agent_installed()
        assert output is True

    @patch('os.path.exists', return_value = False)
    def test_vision_agent_installed_false(self, mock):
        output = is_vision_agent_installed()
        assert output is False
        
