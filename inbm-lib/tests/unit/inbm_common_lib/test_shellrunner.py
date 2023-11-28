from unittest import TestCase
from inbm_common_lib.shell_runner import PseudoShellRunner
from unittest.mock import mock_open, patch, Mock, PropertyMock


class TestShellRunner(TestCase):

    class MockPopen:

        def __init__(self) -> None:
            pass

        def communicate(self, input=None):
            return 'stdout', 'stderr'

        def close(self) -> None:
            pass

    @patch('os.makedirs', return_value=True)
    def test_run_file(self, mock_makedir: Mock) -> None:
        with patch('builtins.open', new_callable=mock_open()) as m:
            mock_popen = TestShellRunner.MockPopen()
            mock_returncode = PropertyMock(return_value=0)
            type(mock_popen).returncode = mock_returncode  # type: ignore

            out, err, return_code, abslogpath = PseudoShellRunner().run_with_log_path(
                "echo TestCase", "/home/fakepath/")
            mock_makedir.assert_called_once()
            self.assertEquals(out, '')

    @patch('os.makedirs', return_value=True)
    def test_run_stdout(self, mock_makedir: Mock) -> None:
        with patch('builtins.open', new_callable=mock_open()) as m:
            mock_popen = TestShellRunner.MockPopen()
            mock_makedir.assert_not_called()
            mock_returncode = PropertyMock(return_value=0)
            type(mock_popen).return_code = mock_returncode  # type: ignore

            out, err, return_code = PseudoShellRunner().run("echo TestCase")
            assert (out == "TestCase\n")

    def test_sanitize(self, filename: str = 'test file/name') -> None:
        self.assertEqual(
            PseudoShellRunner()._sanitize(filename),
            'test_file_name')
