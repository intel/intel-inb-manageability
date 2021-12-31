from unittest import TestCase
from mock import patch


class TestPathPrefixes(TestCase):

    @patch('platform.system', return_value='Windows')
    def test_client_creation(self, platform):
        import inbm_vision_lib.path_prefixes
