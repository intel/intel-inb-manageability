import pytest
from unittest.mock import patch
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.source.linux_gpg_key import remove_gpg_key


class TestLinuxGpgKey:
    @patch("dispatcher.source.linux_gpg_key.PseudoShellRunner.run", return_value=("", "", 0))
    def test_remove_gpg_key_successful(self, mock_run):
        try:
            remove_gpg_key("123456A0")
        except DispatcherException:
            self.fail("Dispatcher remove GPG key raised DispatcherException unexpectedly!")

    @patch("dispatcher.source.linux_gpg_key.PseudoShellRunner.run", return_value=("", "", 2))
    def test_not_raise_when_list_fails(self, mock_run):
        try:
            remove_gpg_key("123456A0")
        except DispatcherException:
            self.fail("Dispatcher remove GPG key raised DispatcherException unexpectedly!")

    # @patch("dispatcher.source.linux_gpg_key.PseudoShellRunner.run",
    #        return_value=[{"", "", 0}, {"", "GPG Delete Error", 1}])
    # def test_raise_when_unable_delete_gpg_key(self, mocker):
    #     shell_runner_mock = mocker.patch(
    #              "dispatcher.source.linux_gpg_key.PseudoShellRunner")
    #     shell_runner_instance = shell_runner_mock.return_value
    #         if isinstance([{"", "", 0}, {"", "GPG Delete Error", 1}], list):  # Simulate sequence of command runs
    #             shell_runner_instance.run.side_effect = [
    #                 (stdout, stderr, code) for stdout, stderr, code in [{"", "", 0}, {"", "GPG Delete Error", 1}]
    #             ]
    #     with patch('dispatcher.source.linux_gpg_key.PseudoShellRunner.run') as mock_run:
    #         mock_run.return_value.json.side_effect = [{"", "", 0}, {"", "GPG Delete Error", 1}]
    #         with pytest.raises(DispatcherException) as ex:
    #             remove_gpg_key("123456A0")
    #         assert str(ex.value) == "Error deleting GPG key: GPG Delete Error"
