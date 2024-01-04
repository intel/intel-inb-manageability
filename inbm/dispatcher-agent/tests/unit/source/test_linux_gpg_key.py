import pytest
from unittest.mock import mock_open, patch

from requests import RequestException
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.source.linux_gpg_key import add_gpg_key, remove_gpg_key
from dispatcher.source.source_exception import SourceError


class TestLinuxGpgKey:
    @patch("dispatcher.source.linux_gpg_key.PseudoShellRunner.run", return_value=("", "", 0))
    def test_remove_gpg_key_successful(self, mock_run):
        try:
            remove_gpg_key("123456A0")
        except DispatcherException:
            self.fail("Remove GPG key raised SourceError unexpectedly!")

    @patch("dispatcher.source.linux_gpg_key.PseudoShellRunner.run", return_value=("", "", 2))
    def test_not_raise_when_list_fails(self, mock_run):
        try:
            remove_gpg_key("123456A0")
        except SourceError:
            self.fail("Remove GPG key raised SourceError unexpectedly!")

    def test_add_gpg_key_success(self, mocker):
        mock_get = mocker.patch("dispatcher.source.linux_gpg_key.requests.get", autospec=True)
        mocker.patch(
            "dispatcher.source.linux_gpg_key.requests.Response.raise_for_status", autospec=True
        )
        mock_get.return_value.content = b"some-gpg-key-data"

        mock_run = mocker.patch("dispatcher.source.linux_gpg_key.subprocess.run", autospec=True)

        remote_key_path = "https://example.com/key.gpg"
        key_store_path = "/etc/apt/trusted.gpg.d/my_key.gpg"
        add_gpg_key(remote_key_path, key_store_path)

        mock_get.assert_called_once_with(remote_key_path)
        mock_run.assert_called_once_with(
            ["/usr/bin/gpg", "--dearmor", "--output", key_store_path],
            input="some-gpg-key-data",
            check=True,
            text=True,
            shell=False,
        )

    def test_add_gpg_key_http_error(self, mocker):
        # Mock requests.get() to raise an HTTP error
        mocker.patch("dispatcher.source.linux_gpg_key.requests.get", side_effect=RequestException)

        # Execute the function and assert that SourceError is raised
        with pytest.raises(SourceError):
            add_gpg_key("https://example.com/key.gpg", "/etc/apt/trusted.gpg.d/my_key.gpg")

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
