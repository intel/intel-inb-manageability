from unittest import TestCase
from unit.common.mock_resources import *
from mock import patch, Mock

from dispatcher.aota.factory import get_app_instance, get_app_os
from dispatcher.aota.aota_command import DockerCompose, Docker
from dispatcher.config_dbs import ConfigDbs
from dispatcher.aota.aota_error import AotaError
from dispatcher.aota.application_command import CentOsApplication, UbuntuApplication

from .test_aota_command import TestAotaCommand

DOCKER_COMPOSE_PARSED_MANIFEST = {'config_params': None, 'version': None,
                                  'container_tag': 'abc', 'uri': 'http://sample/test.tar.gz',
                                  'file': None, 'repo': None,
                                  'cmd': 'pull',
                                  'app_type': 'compose',
                                  'username': 'user', 'password': 'user123',
                                  'docker_registry': None,
                                  'docker_username': None,
                                  'docker_password': None,
                                  'device_reboot': None}

DOCKER_PARSED_MANIFEST = {'config_params': None, 'version': None,
                          'container_tag': 'abc', 'uri': 'file://sample/test.rpm',
                          'file': None, 'repo': None,
                          'cmd': 'load',
                          'app_type': 'docker',
                          'username': None, 'password': None,
                          'docker_registry': None,
                          'docker_username': None,
                          'docker_password': None,
                          'device_reboot': None}

DRIVER_PARSED_MANIFEST = {'config_params': None, 'version': None,
                          'container_tag': 'abc', 'uri': 'file://sample/driver.rpm',
                          'file': None, 'repo': None,
                          'cmd': 'update',
                          'app_type': 'application',
                          'username': None, 'password': None,
                          'docker_registry': None,
                          'docker_username': None,
                          'docker_password': None,
                          'device_reboot': 'Yes'}


class TestFactory(TestCase):

    def setUp(self):
        self.mock_disp_obj = MockDispatcher.build_mock_dispatcher()

    def test_successfully_get_factory_docker_compose(self):
        assert type(get_app_instance("compose", self.mock_disp_obj, DOCKER_COMPOSE_PARSED_MANIFEST,
                                     dbs=ConfigDbs.ON, update_logger=UpdateLogger('', ''))) is DockerCompose

    def test_successfully_get_factory_docker(self):
        assert type(get_app_instance("docker", self.mock_disp_obj, DOCKER_PARSED_MANIFEST,
                                     dbs=ConfigDbs.ON, update_logger=UpdateLogger('', ''))) is Docker

    def test_raise_no_valid_command_type(self):
        with self.assertRaisesRegex(AotaError, "Invalid application type: unknown"):
            get_app_instance("unknown", self.mock_disp_obj, DOCKER_COMPOSE_PARSED_MANIFEST,
                             dbs=ConfigDbs.ON, update_logger=UpdateLogger('', ''))

    @patch('dispatcher.aota.factory.is_inside_container', return_value=True)
    @patch('dispatcher.aota.factory.detect_os', return_value='CentOS')
    def test_successfully_get_factory_cent_os(self, detect_os, is_inside_container):
        assert type(get_app_os(self.mock_disp_obj, DRIVER_PARSED_MANIFEST,
                               dbs=ConfigDbs.ON, update_logger=UpdateLogger('', ''))) is CentOsApplication

    @patch('dispatcher.aota.factory.detect_os', return_value='Ubuntu')
    def test_successfully_get_factory_ubuntu(self, detect_os):
        assert type(get_app_os(self.mock_disp_obj, DOCKER_COMPOSE_PARSED_MANIFEST,
                               dbs=ConfigDbs.ON, update_logger=UpdateLogger('', ''))) is UbuntuApplication

    @patch('dispatcher.aota.factory.detect_os', return_value='RedHat')
    def test_raise_no_application_os(self, detect_os):
        with self.assertRaisesRegex(AotaError, "Application commands are unsupported on the OS: RedHat"):
            get_app_os(self.mock_disp_obj, DOCKER_COMPOSE_PARSED_MANIFEST, dbs=ConfigDbs.ON, update_logger=UpdateLogger('', ''))
