from unittest import TestCase

from dispatcher.source.source_cmd_factory import get_factory, UbuntuOsCommandFactory, UbuntuApplicationCommandFactory
from dispatcher.source.source_adder import UbuntuApplicationSourceAdder, UbuntuOsSourceAdder
from dispatcher.source.source_remover import UbuntuApplicationSourceRemover, UbuntuOsSourceRemover
from dispatcher.source.source_updater import UbuntuApplicationSourceUpdater, UbuntuOsSourceUpdater
from dispatcher.source.source_lister import UbuntuApplicationSourceLister, UbuntuOsSourceLister
from dispatcher.source.constants import OsType, SourceCmdType


class TestBiosFactory(TestCase):
    def test_get_factory_ubuntu_os_type(self) -> None:
        assert type(get_factory(OsType.Ubuntu, SourceCmdType.OS) is UbuntuOsCommandFactory)

    def test_get_ubuntu_os_adder_type(self) -> None:
        self.assertEqual(type(get_factory(OsType.Ubuntu, SourceCmdType.OS).create_adder()), UbuntuOsSourceAdder)

    def test_get_ubuntu_os_remover_type(self) -> None:
        self.assertEqual(type(get_factory(OsType.Ubuntu, SourceCmdType.OS).create_remover()), UbuntuOsSourceRemover)

    def test_get_ubuntu_os_updater_type(self) -> None:
        self.assertEqual(type(get_factory(OsType.Ubuntu, SourceCmdType.OS).create_updater()), UbuntuOsSourceUpdater)

    def test_get_ubuntu_os_lister_type(self) -> None:
        self.assertEqual(type(get_factory(OsType.Ubuntu, SourceCmdType.OS).create_lister()), UbuntuOsSourceLister)

    def test_get_factory_ubuntu_application_type(self) -> None:
        assert type(get_factory(OsType.Ubuntu, SourceCmdType.Application) is UbuntuApplicationCommandFactory)

    def test_get_ubuntu_application_adder_type(self) -> None:
        self.assertEqual(type(get_factory(OsType.Ubuntu, SourceCmdType.Application).create_adder()),
                         UbuntuApplicationSourceAdder)

    def test_get_ubuntu_application_remover_type(self) -> None:
        self.assertEqual(type(get_factory(OsType.Ubuntu, SourceCmdType.Application).create_remover()),
                         UbuntuApplicationSourceRemover)

    def test_get_ubuntu_application_updater_type(self) -> None:
        self.assertEqual(type(get_factory(OsType.Ubuntu, SourceCmdType.Application).create_updater()),
                         UbuntuApplicationSourceUpdater)

    def test_get_ubuntu_application_lister_type(self) -> None:
        self.assertEqual(type(get_factory(OsType.Ubuntu, SourceCmdType.Application).create_lister()),
                         UbuntuApplicationSourceLister)
