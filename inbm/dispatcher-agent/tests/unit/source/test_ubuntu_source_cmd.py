from unittest import mock
import pytest
from unittest.mock import mock_open, patch
from dispatcher.source.source_exception import SourceError
from ..common.mock_resources import MockDispatcherBroker
from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.source.constants import (
    UBUNTU_APT_SOURCES_LIST_D,
    UBUNTU_APT_SOURCES_LIST,
    ApplicationRemoveSourceParameters,
    SourceParameters,
    ApplicationUpdateSourceParameters,
    ApplicationAddSourceParameters
)
from dispatcher.source.ubuntu_source_manager import (
    UbuntuApplicationSourceManager,
    UbuntuOsSourceManager,
)

APP_SOURCE = [
    "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-graphics.gpg] "
    "https://repositories.intel.com/gpu/ubuntu jammy unified",
    "deb-src https://repo.zabbix.com/zabbix/5.0/ubuntu jammy main",
]


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
            with pytest.raises(SourceError) as exc_info:
                command.list()
            assert "Error opening source file" in str(exc_info.value)

    @pytest.mark.parametrize(
        "sources_to_remove, expected_content",
        [
            (
                SourceParameters(sources=["deb http://example.com/ubuntu focal main restricted"]),
                [
                    "# Comment line\n",
                    "deb-src http://example.com/ubuntu focal main restricted\n",
                ],
            ),
            (
                SourceParameters(
                    sources=[
                        "deb http://example.com/ubuntu focal main restricted",
                        "deb-src http://example.com/ubuntu focal main restricted",
                    ]
                ),
                ["# Comment line\n"],
            ),
            (
                SourceParameters(
                    sources=[
                        "non-existent source line",
                    ]
                ),
                [
                    "# Comment line\n",
                    "deb http://example.com/ubuntu focal main restricted\n",
                    "deb-src http://example.com/ubuntu focal main restricted\n",
                ],
            ),
        ],
    )
    def test_remove_sources(self, sources_list_content, sources_to_remove, expected_content):
        initial_content = sources_list_content

        # Mocking open to simulate file read and write operations
        mo = mock_open(read_data=initial_content)
        with patch("builtins.open", mo):
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)

        # Check that the file was opened twice ('r' and 'w')
        assert mo.call_count == 2

        # Check that the exact write calls happened
        assert mo().write.call_count == len(expected_content)
        write_calls = [mock.call(line) for line in expected_content]
        mo().write.assert_has_calls(write_calls, any_order=False)

    def test_remove_raises_dispatcher_exception_on_write_error(self, sources_list_content):
        sources_to_remove = SourceParameters(
            sources=["deb http://example.com/ubuntu focal main restricted"]
        )

        mo = mock_open(read_data=sources_list_content)

        def write_side_effect(*args, **kwargs):
            raise OSError("Write error")

        mo.return_value.write.side_effect = write_side_effect

        with patch("builtins.open", mo), pytest.raises(SourceError) as exc_info:
            manager = UbuntuOsSourceManager()
            manager.remove(sources_to_remove)

        assert "Error occurred while trying to remove sources" in str(exc_info.value)

    def test_ubuntu_os_source_manager_add_success(self):
        test_sources = [
            "deb http://archive.ubuntu.com/ubuntu focal main",
            "deb-src http://archive.ubuntu.com/ubuntu focal main",
        ]
        parameters = SourceParameters(sources=test_sources)

        manager = UbuntuOsSourceManager()

        m = mock_open()
        with patch("builtins.open", m):
            manager.add(parameters)

        m.assert_called_once_with(UBUNTU_APT_SOURCES_LIST, "a")
        m().write.assert_any_call(f"{test_sources[0]}\n")
        m().write.assert_any_call(f"{test_sources[1]}\n")

    def test_ubuntu_os_source_manager_add_error(self):
        test_sources = [
            "deb http://archive.ubuntu.com/ubuntu focal main",
            "deb-src http://archive.ubuntu.com/ubuntu focal main",
        ]
        parameters = SourceParameters(sources=test_sources)

        manager = UbuntuOsSourceManager()

        m = mock_open()
        m.side_effect = OSError("Permission denied")
        with patch("builtins.open", m):
            with pytest.raises(SourceError) as e:
                manager.add(parameters)
            assert str(e.value) == "Error adding sources: Permission denied"

    def test_update_sources_success(self):
        mock_sources = [
            "deb http://archive.ubuntu.com/ubuntu/ bionic universe",
            "deb http://archive.ubuntu.com/ubuntu/ bionic-updates universe",
        ]
        parameters = SourceParameters(sources=mock_sources)
        manager = UbuntuOsSourceManager()
        mock_file = mock_open()

        # Act & Assert
        with patch("builtins.open", mock_file):
            manager.update(parameters)
            mock_file.assert_called_once_with(UBUNTU_APT_SOURCES_LIST, "w")
            mock_file().write.assert_has_calls(
                [mock.call(f"{source}\n") for source in mock_sources]
            )

    def test_update_sources_os_error(self):
        # Arrange
        parameters = SourceParameters(sources=["source"])
        manager = UbuntuOsSourceManager()
        mock_file = mock_open()

        # Simulate an OSError
        mock_file.side_effect = OSError("Mocked error")

        # Act & Assert
        with patch("builtins.open", mock_file):
            with pytest.raises(SourceError) as excinfo:
                manager.update(parameters)
            assert "Error adding sources: Mocked error" in str(excinfo.value)


class TestUbuntuApplicationSourceManager:
    @patch("dispatcher.source.ubuntu_source_manager.verify_source")
    def test_add_app_with_gpg_key_successfully(self, mock_verify_source):
        try:
            params = ApplicationAddSourceParameters(
                sources="deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main",
                gpg_key_uri="https://dl-ssl.google.com/linux/linux_signing_key.pub",
                gpg_key_name="google-chrome.gpg"
            )
            broker = MockDispatcherBroker.build_mock_dispatcher_broker()
            command = UbuntuApplicationSourceManager(broker)
            with (patch("builtins.open", new_callable=mock_open()),
                  patch("dispatcher.source.ubuntu_source_manager.add_gpg_key")):
                command.add(params)
        except SourceError as err:
            pytest.fail(f"'UbuntuApplicationSourceManager.add' raised an exception {err}")

    def test_add_app_deb_822_format_successfully(self):
        broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        try:
            params = ApplicationAddSourceParameters(
                source_list_file_name="google-chrome.sources",
                sources="X-Repolib-Name: Google Chrome"
                        "Enabled: yes"
                        "Types: deb"
                        "URIs: https://dl-ssl.google.com/linux/linux_signing_key.pub"
                        "Suites: stable"
                        "Components: main",
            )
            command = UbuntuApplicationSourceManager(broker)
            with patch("builtins.open", new_callable=mock_open()):
                command.add(params)
        except SourceError as err:
            pytest.fail(f"'UbuntuApplicationSourceManager.add' raised an exception {err}")

    def test_update_app_source_successfully(self):
        try:
            broker = MockDispatcherBroker.build_mock_dispatcher_broker()
            params = ApplicationUpdateSourceParameters(
                source_list_file_name="intel-gpu-jammy.list", sources=APP_SOURCE
            )
            command = UbuntuApplicationSourceManager(broker)
            with patch("builtins.open", new_callable=mock_open()):
                command.update(params)
        except SourceError as err:
            pytest.fail(f"'UbuntuApplicationSourceManager.update' raised an exception {err}")

    # def test_raises_exception_on_io_error_during_update_app_source_ubuntu(self):
    #     params = ApplicationUpdateSourceParameters(file_name="intel-gpu-jammy.list",
    #                                                sources=APP_SOURCE)
    #     command = UbuntuApplicationSourceManager()
    #     with pytest.raises(SourceError) as exc_info:
    #         with patch('builtins.open', new_callable=mock_open(), side_effect=OSError):
    #             command.update(params)
    #     assert "Error while writing file: " in str(exc_info.value)

    def test_list(self, sources_list_d_content):
        with patch("glob.glob", return_value=["/etc/apt/sources.list.d/example.list"]), patch(
            "builtins.open", mock_open(read_data=sources_list_d_content)
        ):
            broker = MockDispatcherBroker.build_mock_dispatcher_broker()
            command = UbuntuApplicationSourceManager(broker)
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
            broker = MockDispatcherBroker.build_mock_dispatcher_broker()
            command = UbuntuApplicationSourceManager(broker)
            with pytest.raises(SourceError) as exc_info:
                command.list()
            assert "Error listing application sources" in str(exc_info.value)

    @patch("dispatcher.source.ubuntu_source_manager.remove_file", return_value=True)
    def test_successfully_remove_gpg_key_and_source_list(
        self, mock_remove_file
    ):
        parameters = ApplicationRemoveSourceParameters(
            gpg_key_name="example_source.gpg", source_list_file_name="example_source.list"
        )
        broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        command = UbuntuApplicationSourceManager(broker)
        try:
            command.remove(parameters)
        except SourceError:
            self.fail("Remove GPG key raised DispatcherException unexpectedly!")

    @patch("dispatcher.source.ubuntu_source_manager.verify_source", side_effect=DispatcherException('error'))
    def test_failed_add_gpg_key_method(self, mock_verify_source):
        parameters = ApplicationAddSourceParameters(
            sources="deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main",
            gpg_key_uri="https://dl-ssl.google.com/linux/linux_signing_key.pub",
            gpg_key_name="name"
        )
        broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        command = UbuntuApplicationSourceManager(broker)
        with pytest.raises(SourceError) as ex:
            command.add(parameters)
        assert str(ex.value) == 'Source Gpg key URI verification check failed: error'


    @patch("dispatcher.source.ubuntu_source_manager.verify_source")
    def test_success_add_gpg_key_method(self, mock_verify_source):
        mock_verify_source.return_value = True 
        parameters = ApplicationAddSourceParameters(
            sources="deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main",
            gpg_key_uri="https://dl-ssl.google.com/linux/linux_signing_key.pub",
            gpg_key_name="name"
        )
        broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        command = UbuntuApplicationSourceManager(broker)
        with (patch("builtins.open", new_callable=mock_open()),
              patch("dispatcher.source.ubuntu_source_manager.add_gpg_key")):    
            command.add(parameters)

    @patch("dispatcher.source.ubuntu_source_manager.remove_gpg_key_if_exists")
    def test_raises_when_space_check_fails(self, mock_remove_gpg_key):
        parameters = ApplicationRemoveSourceParameters(
            gpg_key_name="example_source.gpg", source_list_file_name="../example_source.list"
        )
        broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        command = UbuntuApplicationSourceManager(broker)
        with pytest.raises(SourceError) as ex:
            command.remove(parameters)
        assert str(ex.value) == "Invalid file name: ../example_source.list"

    @patch("dispatcher.source.ubuntu_source_manager.remove_file", return_value=False)
    def test_raises_when_unable_to_remove_file(self, mock_remove_file):
        parameters = ApplicationRemoveSourceParameters(
            gpg_key_name="example_source.gpg", source_list_file_name="example_source.list"
        )
        broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        command = UbuntuApplicationSourceManager(broker)
        with pytest.raises(SourceError) as ex:
            command.remove(parameters)
        assert str(ex.value) == "Error removing file: example_source.list"

    @patch(
        "dispatcher.source.ubuntu_source_manager.os.path.join",
        side_effect=OSError("unable to join path"),
    )
    @patch("dispatcher.source.ubuntu_source_manager.remove_file", return_value=False)
    @patch("dispatcher.source.ubuntu_source_manager.remove_gpg_key_if_exists")
    def test_raises_on_os_error(self, mock_remove_gpg_key, mock_remove_file, mock_os_error):
        parameters = ApplicationRemoveSourceParameters(
            gpg_key_name="example_source.gpg", file_name="example_source.list"
        )
        broker = MockDispatcherBroker.build_mock_dispatcher_broker()
        command = UbuntuApplicationSourceManager(broker)
        with pytest.raises(SourceError) as ex:
            command.remove(parameters)
        assert str(ex.value) == "Error removing file: unable to join path"

