from unittest import mock
import pytest
from unittest.mock import mock_open, patch
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.source.constants import (
    UBUNTU_APT_SOURCES_LIST_D,
    ApplicationRemoveSourceParameters,
    SourceParameters,
)
from dispatcher.source.ubuntu_source_manager import (
    UbuntuApplicationSourceManager,
    UbuntuOsSourceManager,
)


@pytest.fixture
def sources_list_content():
    return (
        "# Comment line\n"
        "deb http://example.com/ubuntu focal main restricted\n"
        "deb-src http://example.com/ubuntu focal main restricted\n"
    )


@pytest.fixture
def sources_list_d_content():
    return (
        "# Another comment line\n"
        "deb http://example.com/ubuntu focal universe\n"
        "deb-src http://example.com/ubuntu focal universe\n"
    )


class TestUbuntuOSSourceManager:
    def test_list(self, sources_list_content):
        with patch("builtins.open", mock_open(read_data=sources_list_content)) as mock_file:
            command = UbuntuOsSourceManager()
            sources = command.list()
            mock_file.assert_called_once_with("/etc/apt/sources.list", "r")
            assert sources == [
                "deb http://example.com/ubuntu focal main restricted",
                "deb-src http://example.com/ubuntu focal main restricted",
            ]

    def test_list_with_oserror_exception(self):
        with patch("builtins.open", side_effect=OSError):
            command = UbuntuOsSourceManager()
            with pytest.raises(DispatcherException) as exc_info:
                command.list()
            assert "Error opening source file" in str(exc_info.value)

    def test_remove_single_source(self, sources_list_content):
        initial_content = sources_list_content
        sources_to_remove = SourceParameters(
            sources=["deb http://example.com/ubuntu focal main restricted"]
        )

        # Expected content after removal:
        expected_content = [
            "# Comment line\n",
            "deb-src http://example.com/ubuntu focal main restricted\n",
        ]

        # Mocking open to simulate file read and write operations
        mo = mock_open(read_data=initial_content)
        with patch("builtins.open", mo):
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)

        # Check that the file was opened twice ('r' and 'w')
        assert mo.call_count == 2
        write_calls = [mock.call(line) for line in expected_content]
        mo().write.assert_has_calls(write_calls, any_order=False)

    def test_remove_multiple_sources(self, sources_list_content):
        initial_content = sources_list_content
        sources_to_remove = SourceParameters(
            sources=[
                "deb http://example.com/ubuntu focal main restricted",
                "deb http://example.com/ubuntu focal main restricted",
            ]
        )

        # Expected content after removal:
        expected_content = ["# Comment line\n"]

        # Mocking open to simulate file read and write operations
        mo = mock_open(read_data=initial_content)
        with patch("builtins.open", mo):
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)

        # Check that the file was opened twice ('r' and 'w')
        assert mo.call_count == 2
        write_calls = [mock.call(line) for line in expected_content]
        mo().write.assert_has_calls(write_calls, any_order=False)

    def test_remove_nonexistent_source(self, sources_list_content):
        initial_content = sources_list_content
        sources_to_remove = SourceParameters(sources=["nonexistent source line"])

        mo = mock_open(read_data=initial_content)
        with patch("builtins.open", mo):
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)

        # Check that the file was opened twice ('r' and 'w')
        assert mo.call_count == 2

        # Check that the file content hasn't changed since the source was not found
        write_calls = [mock.call(line + "\n") for line in initial_content.splitlines()]
        mo().write.assert_has_calls(write_calls, any_order=False)

    def test_remove_raises_dispatcher_exception_on_write_error(self, sources_list_content):
        sources_to_remove = SourceParameters(
            sources=["deb http://example.com/ubuntu focal main restricted"]
        )

        mo = mock_open(read_data=sources_list_content)

        def write_side_effect(*args, **kwargs):
            raise OSError("Write error")

        mo.return_value.write.side_effect = write_side_effect

        with patch("builtins.open", mo), pytest.raises(DispatcherException) as exc_info:
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)

        assert "Error occurred while trying to remove sources" in str(exc_info.value)


class TestUbuntuApplicationSourceManager:
    def test_list(self, sources_list_d_content):
        with patch("glob.glob", return_value=["/etc/apt/sources.list.d/example.list"]), patch(
            "builtins.open", mock_open(read_data=sources_list_d_content)
        ):
            command = UbuntuApplicationSourceManager()
            sources = command.list()
            assert sources[0].name == "example.list"
            assert sources[0].sources == [
                "deb http://example.com/ubuntu focal universe",
                "deb-src http://example.com/ubuntu focal universe",
            ]

    def test_list_raises_exception(self):
        with patch("glob.glob", return_value=["/etc/apt/sources.list.d/example.list"]), patch(
            "builtins.open", side_effect=OSError
        ):
            command = UbuntuApplicationSourceManager()
            with pytest.raises(DispatcherException) as exc_info:
                command.list()
            assert "Error listing application sources" in str(exc_info.value)

    @pytest.mark.parametrize(
        "gpg_key_id, file_name, gpg_run_side_effect, gpg_key_exists, expected_except",
        [
            # Case: Successful removal of GPG key and source file
            ("123456A0", "example_source.list", [(0, "", 0), (0, "", 0)], True, None),
            # Case: GPG key does not exist, but the source file is still removed
            ("123456A1", "example_source.list", [(1, "No such key", 1)], False, None),
            # Case: GPG exists but fails to delete, expect DispatcherException
            (
                "123456A2",
                "example_source.list",
                [(0, "", 0), (1, "GPG Delete Error", 1)],
                True,
                DispatcherException,
            ),
            # Case: OSError on checking GPG key, expect DispatcherException
            ("123456A3", "example_source.list", OSError("GPG Error"), True, DispatcherException),
            # Case: OSError on removing the file, expect DispatcherException
            (
                "123456A4",
                "example_source.list",
                [(0, "", 0), (0, "", 0)],
                True,
                DispatcherException,
            ),
        ],
    )
    def test_ubuntu_application_source_manager_remove(
        self, gpg_key_id, file_name, gpg_run_side_effect, gpg_key_exists, expected_except, mocker
    ):
        parameters = ApplicationRemoveSourceParameters(gpg_key_id=gpg_key_id, file_name=file_name)

        # Mock PseudoShellRunner and its run method
        shell_runner_mock = mocker.patch(
            "dispatcher.source.ubuntu_source_manager.PseudoShellRunner"
        )
        shell_runner_instance = shell_runner_mock.return_value
        if isinstance(gpg_run_side_effect, list):  # Simulate sequence of command runs
            shell_runner_instance.run.side_effect = [
                (stdout, stderr, code) for stdout, stderr, code in gpg_run_side_effect
            ]
        else:  # Directly raise OSError
            shell_runner_instance.run.side_effect = gpg_run_side_effect

        # Mock os.remove based on whether we expect an exception for file removal or not
        os_remove_mock = mocker.patch("os.remove")
        if expected_except is DispatcherException and gpg_run_side_effect == [
            (0, "", 0),
            (0, "", 0),
        ]:
            os_remove_mock.side_effect = OSError("File could not be removed")

        if expected_except:
            # If we expect an exception, check that it is raised
            with pytest.raises(expected_except):
                command = UbuntuApplicationSourceManager()
                command.remove(parameters)
        else:
            # If no exception is expected, perform the operation and assert mocks are called as expected
            command = UbuntuApplicationSourceManager()
            command.remove(parameters)

            # Check GPG command runs
            expected_gpg_calls = [mocker.call(f"gpg --list-keys {gpg_key_id}")]
            if gpg_key_exists:
                expected_gpg_calls.append(mocker.call(f"gpg --delete-key {gpg_key_id}"))
            shell_runner_instance.run.assert_has_calls(expected_gpg_calls)

            # Check file removal
            os_remove_mock.assert_called_once_with(UBUNTU_APT_SOURCES_LIST_D + "/" + file_name)

            # Note: UBUNTU_APT_SOURCES_LIST_D should be a string constant representing the
            # path under which Ubuntu stores source files, e.g., "/etc/apt/sources.list.d"
