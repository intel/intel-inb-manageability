from mock import patch, mock_open
from unittest import TestCase
from node.mender_util import read_current_mender_version


class TestMenderUtil(TestCase):

    def test_return_artifact(self):
        with patch("builtins.open", mock_open(read_data=b"artifact_name=Release-20201013085007")) as mock_file:
            self.assertEqual(read_current_mender_version(), "Release-20201013085007")
