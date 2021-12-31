import testtools
from inbm_vision_lib.shell_runner import PseudoShellRunner
from mock import mock_open, patch
import mock


class TestShellRunner(testtools.TestCase):

    class MockPopen:

        def __init__(self):
            pass

        def communicate(self, input=None):
            return 'stdout', 'stderr'

        def close(self):
            pass

    def test_run_stdout(self):
        with patch('builtins.open', new_callable=mock_open()):
            mock_popen = TestShellRunner.MockPopen()
            mock_returncode = mock.PropertyMock(return_value=0)
            type(mock_popen).return_code = mock_returncode  # type: ignore

            out, err, return_code = PseudoShellRunner.run("echo TestCase")
            assert (out == "TestCase\n")
