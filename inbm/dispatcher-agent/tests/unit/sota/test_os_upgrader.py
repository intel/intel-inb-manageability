import unittest
import os
from typing import Optional

from ..common.mock_resources import *
from dispatcher.sota.os_factory import SotaOsFactory
from dispatcher.sota.snapshot import *
from dispatcher.sota.sota import SOTA
from inbm_lib.xmlhandler import XmlHandler
from dispatcher.packagemanager.memory_repo import MemoryRepo

TEST_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                    '../../../fpm-template/usr/share/dispatcher-agent/'
                                    'manifest_schema.xsd')


class TestOsUpgrader(unittest.TestCase):
    sota_instance: Optional[SOTA] = None
    resource = {'': ''}
    mock_disp_callbacks_obj: DispatcherCallbacks

    @classmethod
    def setUpClass(cls):
        cls.mock_disp_callbacks_obj = MockDispatcherCallbacks.build_mock_dispatcher_callbacks()

        assert cls.mock_disp_callbacks_obj is not None
        parsed = XmlHandler(fake_sota_success, is_file=False, schema_location=TEST_SCHEMA_LOCATION)
        cls.resource = parsed.get_children('ota/type/sota')
        parsed_manifest = {'resource': cls.resource,
                           'callback': cls.mock_disp_callbacks_obj, 'signature': None, 'hash_algorithm': None,
                           'uri': mock_url, 'repo': TestOsUpgrader._build_mock_repo(0), 'username': username,
                           'password': password, 'sota_mode': 'download-only', 'deviceReboot': "no"}
        sota_instance = SOTA(parsed_manifest, "remote", DispatcherCallbacks(install_check=cls.mock_disp_callbacks_obj.install_check,
                                                                            broker_core=MockDispatcherBroker.build_mock_dispatcher_broker(),
                                                                            sota_repos=cls.mock_disp_callbacks_obj.sota_repos,
                                                                            proceed_without_rollback=cls.mock_disp_callbacks_obj.proceed_without_rollback,
                                                                            logger=cls.mock_disp_callbacks_obj.logger),
                             snapshot=1)

        sota_instance.factory = SotaOsFactory(cls.mock_disp_callbacks_obj).get_os('Ubuntu')
        assert sota_instance.factory
        sota_instance.installer = sota_instance.factory.create_os_upgrader()
        cls.sota_instance = sota_instance

    def test_upgrade(self):
        assert TestOsUpgrader.sota_instance
        installer = TestOsUpgrader.sota_instance.installer
        x_cmd_list = installer.upgrade()  # type: ignore
        cmd_list = ["do-release-upgrade -f DistUpgradeViewNonInteractive"]

        def get_next_index_up():
            j = 0
            while j < len(x_cmd_list):
                yield j
                j = j + 1

        gen = get_next_index_up()
        for each in cmd_list:
            assert (each == x_cmd_list[next(gen)].text)

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo("test")
        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add("test" + str(i + 1) + ".rpm", b"0123456789")
        return mem_repo
