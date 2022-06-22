import unittest
import os
from unittest import TestCase

from dispatcher.aota.aota import AOTA
from dispatcher.aota.aota_command import Docker, DockerCompose
from dispatcher.aota.aota_command import DirectoryRepo
from dispatcher.aota.aota_error import AotaError
from dispatcher.aota.constants import SupportedDriver
from ..common.mock_resources import *
from mock import patch
from typing import Any
from dispatcher.common.result_constants import (
    INSTALL_SUCCESS,
    INSTALL_FAILURE,
    COMMAND_SUCCESS,
    UNABLE_TO_DOWNLOAD_APPLICATION_PACKAGE,
    UNABLE_TO_DOWNLOAD_DOCKER_COMPOSE
)

from dispatcher.dispatcher_exception import DispatcherException
from dispatcher.packagemanager import package_manager
from dispatcher.packagemanager.memory_repo import MemoryRepo
from inbm_common_lib.utility import canonicalize_uri
from inbm_lib.trtl import Trtl

SCHEMA_LOCATION = './packaging/config/manifest_schema.xsd'


class TestAOTA(TestCase):

    @patch('os.rmdir')
    @patch('dispatcher.aota.aota_command.get', return_value=Result(400, "Unable to download application package."))
    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.aota_command.AotaCommand.create_repository_cache_repo')
    def test_failure_one_application_update(self, mock_create_repo, mock_verify_source, mock_get_file, mock_osdir):
        aota = TestAOTA._build_aota(uri='file://sample/test.tar',
                                    app_type='application', cmd='update')
        with self.assertRaisesRegex(AotaError, UNABLE_TO_DOWNLOAD_APPLICATION_PACKAGE.message):
            aota.run()

    def test_application_update_fail(self):
        a = TestAOTA._build_aota(app_type='application', cmd='update')
        with self.assertRaisesRegex(AotaError, 'missing URL.'):
            a.run()

    @patch('os.rmdir')
    @patch('dispatcher.aota.application_command.get', return_value=Result(200, "ok"))
    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.aota_command.AotaCommand.create_repository_cache_repo')
    @patch('dispatcher.aota.factory.detect_os', return_value='Ubuntu')
    @patch('dispatcher.aota.aota_command.DirectoryRepo.get_repo_path', return_value='abc/bdb')
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=['', 'update failed', 2])
    @patch('dispatcher.aota.aota.cleanup_repo')
    @patch('dispatcher.aota.application_command.is_inside_container', return_value=False)
    def test_raise_when_application_update_fails(self, check_os, mock_cleanup, mock_shell, mock_get_repo, mock_platform,
                                                 mock_create_repo,
                                                 mock_verify_source, mock_get_file, mock_osdir):
        mock_create_repo.return_value = DirectoryRepo(os.path.join('abc', "aota"))
        aota = TestAOTA._build_aota(uri='file://sample/test.tar',
                                    app_type='application', cmd='update')
        with self.assertRaisesRegex(AotaError, 'AOTA application update FAILED: update failed'):
            aota.run()
            mock_cleanup.assert_called_once()

    @patch('dispatcher.aota.checker.verify_source')
    def test_fails_install_with_resource_type_empty(self, mock_verify_source):
        a = TestAOTA._build_aota(
            uri='file://sample/test.rpm', container_tag='abc', cmd='up', app_type='compose')
        with self.assertRaisesRegex(AotaError, 'AOTA compose up FAILED: Unable to download docker-compose container.'):
            a.run()

    @patch('dispatcher.aota.checker.verify_source', side_effect='Invalid package should be .tar or .tgz')
    def test_fails_source_verification_check(self, mock_verify_source):
        aota = TestAOTA._build_aota(uri='file://sample/test.rpm', app_type='docker',
                                    container_tag='abc', cmd='load')
        with self.assertRaisesRegex(AotaError, 'AOTA docker load FAILED: Invalid package type; should be .tar or .tgz'):
            aota.run()

    @patch('dispatcher.aota.checker.verify_source')
    def test_fails_package_name_load(self, mock_verify_source):
        aota = TestAOTA._build_aota(uri='file://sample/test.rpm',
                                    container_tag='abc', app_type='docker', cmd='load')
        with self.assertRaisesRegex(AotaError, 'Invalid package type; should be .tar or .tgz'):
            aota.run()

    @patch('os.rmdir')
    @patch('dispatcher.aota.aota_command.TrtlContainer.image_load', return_value=INSTALL_SUCCESS)
    @patch('dispatcher.aota.aota_command.get', return_value=Result(200, "OK"))
    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.application_command.AotaCommand.create_repository_cache_repo')
    def test_success_load(self, mock_create_repo, mock_verify_source, mock_get_file, mock_image_load, mock_osdir):
        aota = TestAOTA._build_aota(uri='file://sample/test.tar', app_type='docker',
                                    container_tag='abc', cmd='load', instance='docker')
        try:
            self.assertEquals(None, aota.load())
        except AotaError:
            self.fail("Exception raised when not expected.")

    @patch('os.rmdir')
    @patch('dispatcher.aota.aota_command.TrtlContainer.image_load', return_value=INSTALL_FAILURE)
    @patch('dispatcher.aota.aota_command.get', return_value=INSTALL_FAILURE)
    @patch('dispatcher.aota.checker.verify_source')
    def test_fail_load(self, mock_verify_source, mock_get_file, mock_image_load, mock_osdir):
        aota = TestAOTA._build_aota(uri='file://sample/test.tar',
                                    container_tag='abc', cmd='load', app_type='docker')
        with self.assertRaisesRegex(AotaError, INSTALL_FAILURE.message):
            aota.run()

    def test_exception(self):
        x = TestAOTA._build_mock_repo(0)
        with self.assertRaises(ValueError):
            package_manager.get(canonicalize_uri(''), x, 0)

    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo('test')

        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add('test' + str(i + 1) + '.rpm', b'0123456789')
        return mem_repo

    @patch('inbm_lib.trtl.Trtl.image_pull_public', return_value=["", "", 0])
    @patch('dispatcher.aota.aota_command.DockerCompose._download')
    def test_compose_pull_success(self, mock_download, mock_pull):
        aota = TestAOTA._build_aota(container_tag='abc', uri='https://sample/test.tar.gz',
                                    cmd='pull',
                                    app_type='compose', username='tj', password='tj123')
        try:
            aota.run()
        except AotaError as e:
            self.fail(f'AotoError raised when not expected: {e}')

    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.aota_command.get', return_value=dummy_success)
    def test_http_server_username_password(self, mock_get_repo, mock_verify_source):
        aota = TestAOTA._build_aota(container_tag='abc', uri='http://sample/test.tar.gz',
                                    cmd='pull',
                                    app_type='compose', username='tj', password='tj123')
        with self.assertRaisesRegex(AotaError, 'Bad request: username/password will not be processed on HTTP server'):
            aota.run()

    def test_compose_list_with_no_container_tag(self):
        aota = TestAOTA._build_aota(app_type='compose', cmd='list')
        with self.assertRaisesRegex(
                AotaError, 'AOTA compose list FAILED: missing container tag.'):
            aota.run()

    def test_docker_pull_no_password(self):
        aota = TestAOTA._build_aota(app_type='docker', cmd='pull', container_tag="hello",
                                    docker_username='user', docker_registry="https://www.example.com/")
        with self.assertRaisesRegex(
                AotaError, 'Missing docker password in Manifest'):
            aota.run()

    def test_docker_pull_no_username(self):
        aota = TestAOTA._build_aota(app_type='docker', cmd='pull', container_tag="hello",
                                    docker_password='pwd', docker_registry="https://www.example.com/")
        with self.assertRaisesRegex(
                AotaError, 'Missing docker username in Manifest'):
            aota.run()

    @patch('inbm_lib.trtl.Trtl.remove_old_images', return_value=None)
    @patch('dispatcher.aota.aota_command.Docker.pull')
    def test_docker_pull_called(self, mock_docker_pull, mock_trtl_pull):
        aota = TestAOTA._build_aota(app_type='docker', cmd='pull', container_tag="hello-world")
        aota.run()
        mock_docker_pull.assert_called_once()
        mock_trtl_pull.assert_not_called()

    @patch('inbm_lib.trtl.Trtl.image_pull_public', return_value=["", "", 0])
    @patch('inbm_lib.trtl.Trtl.remove_old_images', return_value=None)
    def test_docker_pull_public_success(self, mock_trtl_old, mock_trtl_pull):
        aota = TestAOTA._build_aota(app_type='docker', cmd='pull', container_tag="hello",
                                    docker_registry='https://docker.hub')
        try:
            aota.run()
        except AotaError:
            self.fail('AotaError received when not expected')

    def test_application_up_fail(self):
        aota = TestAOTA._build_aota(app_type='application', cmd='up')
        with self.assertRaisesRegex(
                AotaError, 'AOTA application up FAILED: Unsupported Application command: up'):
            aota.run()

    def test_compose_up_fail_one(self):
        aota = TestAOTA._build_aota(app_type='compose', cmd='update',
                                    container_tag="hello",
                                    docker_registry="https://www.example.com/",
                                    uri='file://sample/test.tar.gz')
        with self.assertRaisesRegex(
                AotaError, 'Unsupported Docker Compose command: update'):
            aota.run()

    def test_compose_update_fail(self):
        aota = TestAOTA._build_aota(app_type='compose', cmd='up', container_tag='abc')
        with self.assertRaisesRegex(
                AotaError, 'AOTA compose up FAILED: fetch URI is required.'):
            aota.run()

    def test_docker_update_fail(self):
        aota = TestAOTA._build_aota(app_type='docker', cmd='update')
        with self.assertRaisesRegex(
                AotaError, 'Unsupported Docker command: update'):
            aota.run()

    def test_docker_up_fail(self):
        aota = TestAOTA._build_aota(app_type='docker', cmd='up', container_tag="hello",
                                    docker_registry="https://www.example.com/")
        with self.assertRaisesRegex(
                AotaError, 'Unsupported Docker command: up'):
            aota.run()

    @patch('dispatcher.aota.checker.verify_source')
    def test_compose_docker_update_fail(self, mock_verify_source):
        mock_verify_source.return_value = True
        aota = TestAOTA._build_aota(app_type='compose', cmd='update', container_tag="hello",
                                    uri='file://sample/test.tar.gz')
        with self.assertRaisesRegex(
                AotaError, 'Unsupported Docker Compose command: update'):
            aota.run()

    @patch('dispatcher.aota.aota_command.DockerCompose.down')
    def test_docker_compose_down_function_called(self, mock_docker_down):
        aota = TestAOTA._build_aota(app_type='compose', cmd='down', container_tag="hello",
                                    docker_registry="https://www.example.com/")
        aota.run()
        mock_docker_down.assert_called_once()

    def test_docker_down_fail(self):
        aota = TestAOTA._build_aota(app_type='docker', cmd='down', container_tag="hello",
                                    docker_registry="https://www.example.com/")
        with self.assertRaisesRegex(
                AotaError, 'Unsupported Docker command: down'):
            aota.run()

    @patch('inbm_lib.trtl.Trtl.image_pull_public', return_value=["", "", 3])
    def test_docker_pull_public_fail(self, mock_trtl):
        aota = TestAOTA._build_aota(app_type='docker', cmd='pull', container_tag="hello",
                                    docker_registry='https://docker.hub')
        with self.assertRaisesRegex(AotaError, ''):
            aota.run()

    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.aota_command.get', return_value=dummy_success)
    def test_docker_login_no_password(self, mock_get_repo, mock_verify_source):
        aota = TestAOTA._build_aota(container_tag='abc', uri='file://sample/test.tar.gz', cmd='pull',
                                    app_type='compose',
                                    need_repo=False,
                                    docker_registry='amr-registry-pre.caas.intel.com',
                                    docker_username='tj')
        with self.assertRaisesRegex(AotaError, 'Missing docker password in Manifest'):
            aota.run()

    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.aota_command.get', return_value=dummy_success)
    def test_docker_login_no_username(self, mock_get_repo, mock_verify_source):
        aota = TestAOTA._build_aota(container_tag='abc', uri='file://sample/test.tar.gz', cmd='pull',
                                    app_type='compose',
                                    need_repo=False,
                                    docker_registry='amr-registry-pre.caas.intel.com',
                                    docker_password='tj123')
        with self.assertRaisesRegex(AotaError, 'Missing docker username in Manifest'):
            aota.run()

    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.aota_command.get', return_value=dummy_success)
    def test_docker_login_no_registry_url(self, mock_get_repo, mock_verify_source):
        aota = TestAOTA._build_aota(container_tag='abc', uri='file://sample/test.tar.gz', cmd='pull',
                                    app_type='compose',
                                    need_repo=False, docker_username='tj', docker_password='tj123')
        with self.assertRaisesRegex(AotaError, 'Missing Docker private registry URL in Manifest'):
            aota.run()

    @staticmethod
    def _build_aota(num_files=0, container_tag=None, uri=None, cmd=None,
                    app_type=None, need_repo=True, file=None,
                    username=None, password=None, docker_registry=None, docker_username=None,
                    docker_password=None, instance=None, device_reboot=None):

        if need_repo:
            parsed_manifest = {'config_params': None, 'version': None,
                               'container_tag': container_tag, 'uri': uri,
                               'file': file,
                               'cmd': cmd, 'repo': TestAOTA._build_mock_repo(num_files),
                               'app_type': app_type,
                               'username': username, 'password': password,
                               'docker_registry': docker_registry,
                               'docker_username': docker_username,
                               'docker_password': docker_password,
                               'device_reboot': device_reboot}
        else:
            parsed_manifest = {'config_params': None, 'version': None,
                               'container_tag': container_tag, 'uri': uri,
                               'file': file,
                               'cmd': cmd, 'app_type': app_type, 'username': username,
                               'password': password,
                               'docker_registry': docker_registry,
                               'docker_username': docker_username,
                               'docker_password': docker_password,
                               'device_reboot': device_reboot}
        if instance == 'compose':
            return DockerCompose(MockDispatcherCallbacks.build_mock_dispatcher_callbacks(),
                                 parsed_manifest=parsed_manifest,
                                 dbs=ConfigDbs.ON)
        elif instance == 'docker':
            return Docker(MockDispatcherCallbacks.build_mock_dispatcher_callbacks(),
                          parsed_manifest=parsed_manifest,
                          dbs=ConfigDbs.ON)
        else:
            return AOTA(MockDispatcherCallbacks.build_mock_dispatcher_callbacks(),
                        parsed_manifest=parsed_manifest,
                        dbs=ConfigDbs.ON)

    @patch('inbm_lib.trtl.Trtl.login', return_value=("", "", 0))
    def test_docker_login_success(self, mock_login) -> Any:

        aota = self._build_aota(instance='docker', docker_username='username',
                                docker_password='password', docker_registry='foo')
        result = aota.docker_login()
        self.assertEqual(None, result)

    @patch('inbm_lib.trtl.Trtl.login', return_value=("", "", 1))
    def test_docker_login_fail(self, mock_login) -> Any:

        aota = self._build_aota(instance='docker')
        try:
            aota.docker_login()
            self.fail("Expected AotaError")
        except AotaError as e:
            self.assertEqual("Docker Registry is required for Docker Login.", str(e))

    @patch('dispatcher.aota.checker.verify_source')
    @patch.object(Trtl, 'up', return_value=("", "", 0))
    @patch('dispatcher.aota.aota_command.get', return_value=Result(200, "OK"))
    def test_compose_up_success(self, mock_start, mock_get, mock_verify):
        try:
            aota = self._build_aota(uri='file://sample/test.tar', instance='compose', app_type='compose', cmd='up',
                                    container_tag='abc')
            aota.up()
        except AotaError:
            self.fail("Exception raised when not expected.")

    @patch('dispatcher.aota.checker.verify_source')
    @patch.object(Trtl, 'start', return_value=("", "", 0))
    @patch('dispatcher.aota.aota_command.get', return_value=Result(404, "Not Found"))
    def test_raises_compose_up_unable_to_get_package(self, mock_start, mock_get, mock_verify):
        aota = self._build_aota(instance='compose', container_tag='abc',
                                uri='file://sample/test.tar')
        with self.assertRaisesRegex(AotaError, UNABLE_TO_DOWNLOAD_DOCKER_COMPOSE.message):
            aota.up()

    @patch.object(Trtl, 'stop_all', return_value=("", "", 0))
    def test_raise_When_docker_down_missing_container_tag(self, mock_down):
        aota = self._build_aota(cmd='down', app_type='docker', instance='docker')
        try:
            aota.down()
        except AotaError as e:
            self.assertEqual('missing container tag.', str(e))

    @patch.object(Trtl, 'image_remove_all', return_value=("", "", 0))
    @patch.object(Trtl, 'down', return_value=("", "", 0))
    def test_compose_remove_success(self, mock_down, mock_remove):
        aota = self._build_aota(container_tag='abc', cmd='remove',
                                app_type='compose', instance='compose')
        try:
            aota.remove()
        except AotaError as e:
            self.fail(f'AotaError when not expected: {e}')

    @patch.object(Trtl, 'image_remove_all', return_value=("", "couldn't remove image: abc", 1))
    @patch.object(Trtl, 'stop_all', return_value=("", "", 0))
    def test_docker_remove(self, mock_stop, mock_remove):
        aota = self._build_aota(container_tag='abc', cmd='remove',
                                app_type='docker', instance='docker')
        try:
            aota.remove()
        except AotaError as e:
            self.assertEqual("couldn't remove image: abc", str(e))

    @patch('dispatcher.aota.aota_command.Docker.down', return_value=COMMAND_SUCCESS)
    @patch.object(Trtl, 'image_remove_all', return_value=("", "", 0))
    @patch.object(Trtl, 'stop_all', return_value=("", "", 0))
    @patch('dispatcher.aota.aota_command.DirectoryRepo.exists', return_value=True)
    @patch('shutil.rmtree')
    def test_docker_remove_cleanup_dir(self,
                                       mock_rmtree,
                                       mock_exists,
                                       mock_stop,
                                       mock_remove,
                                       mock_docker_down) -> Any:

        aota = self._build_aota(container_tag='abc', cmd='remove',
                                app_type='docker', instance='docker')
        aota.remove()

    @patch.object(Trtl, 'stop_all', return_value=("", "", 0))
    def test_docker_down(self, mock_trtl):

        aota = self._build_aota(container_tag='abc', cmd='down', app_type='docker')
        with self.assertRaisesRegex(AotaError, 'Unsupported Docker command: down'):
            aota.run()

    @patch.object(Trtl, 'stop_all', return_value=("", "", 0))
    def test_docker_remove_missing_container_tag(self, mock_stop):
        aota = self._build_aota(cmd='remove', app_type='docker', instance='docker')
        try:
            aota.remove()
        except AotaError as e:
            self.assertEqual("missing container tag.", str(e))

    @patch.object(Trtl, 'stats', return_value="container stats here")
    def test_docker_stats_success(self, mock_stats):
        aota = self._build_aota(cmd='stats', app_type='docker')
        res = aota.run()
        self.assertEqual(None, res)

    @patch('dispatcher.aota.aota_command.Docker.stats')
    def test_docker_stats_failed(self, mock_stats):
        aota = self._build_aota(cmd='stats', app_type='docker')
        aota.run()
        mock_stats.assert_called_once()

    @patch('os.rmdir')
    def test_compose_pull_no_uri(self, mock_rmdir):
        aota = self._build_aota(cmd='pull', app_type='compose', container_tag='abc')
        with self.assertRaisesRegex(AotaError, "AOTA compose pull FAILED: fetch URI is required."):
            aota.run()

    @patch('dispatcher.aota.checker.verify_source')
    def test_raise_when_container_tag_empty(self, mock_verify_source):
        aota = TestAOTA._build_aota(
            cmd='up', uri='file://sample/test.rpm', container_tag='', app_type='compose')
        with self.assertRaisesRegex(AotaError, "AOTA compose up FAILED: missing container tag."):
            aota.run()

    @patch('dispatcher.aota.checker.verify_source', side_effect=DispatcherException('Error'))
    def test_fails_source_verification_check_http(self, mock_verify_source):
        aota = TestAOTA._build_aota(uri='http://sample/test.rpm', app_type='docker',
                                    container_tag='abc', cmd='load')
        with self.assertRaisesRegex(AotaError, 'AOTA docker load FAILED: Source verification check failed'):
            aota.run()

    @patch('os.rmdir')
    @patch('dispatcher.aota.aota_command.DockerCompose.up')
    @patch('dispatcher.aota.checker.verify_source')
    def test_run_command_compose_up_no_error(self, mock_verify_source, mock_composeup, mock_rmdir):
        aota = self._build_aota(cmd='up', app_type='compose', uri='http://sample/test.rpm',
                                container_tag='abc')
        res = aota.run()
        self.assertTrue(mock_composeup.called)
        self.assertEqual(res, None)

    @patch('dispatcher.aota.checker.verify_source')
    @patch.object(Trtl, 'login', return_value=("", "", 3))
    def test_run_command_compose_up_error(self, mock_image_pull_private, mock_verify_source):
        aota = self._build_aota(app_type='compose', cmd='up', container_tag="hello",
                                docker_username='user', docker_registry="https://www.example.com/",
                                docker_password='pwd', uri='https://sample/test.rpm')
        with self.assertRaisesRegex(AotaError, "AOTA compose up FAILED: Docker Login Failed"):
            aota.run()

    @patch('os.rmdir')
    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.aota_command.get', return_value=Result(CODE_NOT_FOUND, 'Not Found'))
    def test_run_command_compose_pull_download_error(self,
                                                     mock_get,
                                                     mock_verify_source,
                                                     mock_rmdir) -> Any:

        aota = self._build_aota(cmd='pull', app_type='compose', uri='http://sample/test.rpm',
                                container_tag='abc')
        with self.assertRaisesRegex(AotaError,
                                    "AOTA compose pull FAILED: Unable to download docker-compose container."):
            aota.run()

    @patch('os.rmdir')
    @patch('dispatcher.aota.aota_command.DockerCompose.docker_login')
    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.aota_command.get', return_value=Result(CODE_NOT_FOUND, 'Not Found'))
    def test_run_command_compose_pull_with_login_call_error(self,
                                                            mock_get,
                                                            mock_verify_source,
                                                            mock_docker_login,
                                                            mock_rmdir):

        aota = self._build_aota(app_type='compose', cmd='pull', container_tag="hello",
                                docker_username='user', docker_registry="https://www.example.com/",
                                docker_password='pwd', uri="http://example.com")
        with self.assertRaisesRegex(AotaError,
                                    "AOTA compose pull FAILED: Unable to download docker-compose container."):
            aota.run()
            mock_docker_login.assert_called()

    @patch('dispatcher.aota.aota_command.DockerCompose.list')
    def test_compose_list(self, mock_list):

        aota = self._build_aota(cmd='list', app_type='compose')
        aota.run()
        mock_list.assert_called_once()

    @patch('inbm_lib.trtl.Trtl.list', return_value=[2, 'could not find tag'])
    def test_compose_list_fail(self, mock_list):

        aota = self._build_aota(cmd='list', app_type='compose', container_tag='abc')
        with self.assertRaisesRegex(AotaError, 'AOTA compose list FAILED: could not find tag'):
            aota.run()

    def test_run_cmd_down(self):
        aota = self._build_aota(cmd='down', app_type='compose')
        try:
            aota.run()
        except AotaError as e:
            self.assertEquals('AOTA compose down FAILED: missing container tag.', str(e))

    @patch('inbm_lib.trtl.Trtl.remove_old_images', return_value=None)
    @patch('dispatcher.aota.checker.verify_source')
    @patch('os.rmdir')
    @patch('dispatcher.aota.aota_command.TrtlContainer.image_import', return_value=Result(200, 'Success'))
    def test_run_cmd_import_with_tag(self, mock_image_import, mock_rmdir, mock_verify, mock_remove):
        aota = self._build_aota(cmd='import', app_type='docker',
                                container_tag='foo', uri="http://example.com")
        aota.run()
        mock_image_import.assert_called()

    @patch('dispatcher.aota.checker.verify_source')
    @patch('os.rmdir')
    @patch('dispatcher.packagemanager.memory_repo.MemoryRepo.delete')
    @patch('dispatcher.aota.aota_command.TrtlContainer.image_import')
    def test_run_cmd_import_clean_up_called(self, mock_trtl_cntr, mock_delete, mock_rmdir, mock_verify):
        aota = self._build_aota(cmd='import', app_type='docker',
                                container_tag='foo', instance='docker', uri="http://example.com")
        aota._repo_to_clean_up = DirectoryRepo('abc')
        mock_trtl_cntr.return_value = Result(400, 'Fail')
        try:
            aota.import_image()
            mock_delete.assert_called_once()
        except AotaError as e:
            self.assertEquals('Fail', str(e))

    @patch('os.rmdir')
    @patch('dispatcher.aota.aota_command.TrtlContainer.image_import')
    def test_run_cmd_import_without_tag(self, mock_image_import, mock_rmdir):
        aota = self._build_aota(cmd='import', app_type='docker', container_tag=None)
        with self.assertRaisesRegex(AotaError, 'AOTA docker import_image FAILED: missing container tag.'):
            aota.run()
            mock_image_import.assert_not_called()

    @patch('dispatcher.aota.aota_command.DockerCompose._download', return_value=COMMAND_SUCCESS)
    @patch('inbm_lib.trtl.Trtl.image_pull_public', return_value=["", "Error", 2])
    def test_raise_compose_pull_missing_container_tag(self, mock_image_pull_public, mock_compose_download):
        aota = self._build_aota(cmd='pull', app_type='compose', instance='compose')
        try:
            aota.pull()
        except AotaError as e:
            self.assertEquals("missing container tag.", str(e))

    @patch('dispatcher.aota.aota_command.DockerCompose.list')
    def test_run_command_list_success(self, mock_cmd_list):
        aota = self._build_aota(cmd='list', app_type='compose', container_tag="abc")
        aota.run()
        mock_cmd_list.assert_called_once()

    def test_run_command_remove_raise_error(self):
        aota = self._build_aota(cmd='remove', app_type='docker')
        try:
            aota.run()
        except AotaError as e:
            self.assertEquals(
                "AOTA docker remove FAILED: missing container tag.", str(e))

    @patch('dispatcher.aota.aota_command.Docker.down', return_value=COMMAND_SUCCESS)
    @patch('inbm_lib.trtl.Trtl.image_remove_all', return_value=["", "", 0])
    @patch('dispatcher.aota.aota_command.Docker.remove')
    def test_run_command_remove_function_called(self, mock_a, mock_image_remove_all, mock_docker_down):
        aota = self._build_aota(cmd='remove', app_type='docker')
        aota.run()
        mock_a.assert_called()

    # def test_perform_docker_authentication_field_check(self) -> Any:
    #
    #     aota = self._build_aota(app_type='compose', cmd='pull', container_tag="hello",
    #                             docker_username='us er', docker_registry="https://www.example.com/",
    #                             docker_password='pwd', uri="http://example.com")
    #     try:
    #         aota._perform_docker_authentication_field_check()
    #     except AotaError as e:
    #         self.assertEquals("No spaces allowed in Docker Username/Registry", str(e))

    @patch('dispatcher.aota.application_command.is_inside_container', return_value=False)
    @patch('dispatcher.aota.checker.check_url')
    def test_application_centos_driver_update_raise_error_not_in_container(self, check_url, mock_detect_os):
        aota = self._build_aota(cmd='update', app_type='application',
                                uri="http://example.com", device_reboot="Yes")
        self.assertRaises(AotaError, aota.run)

    @patch('dispatcher.aota.aota_command.get', return_value=Result(200, "OK"))
    @patch('dispatcher.aota.checker.verify_source')
    @patch('dispatcher.aota.application_command.AotaCommand.create_repository_cache_repo')
    @patch('dispatcher.aota.application_command.is_inside_container', return_value=True)
    @patch('dispatcher.aota.factory.detect_os', return_value='CentOS')
    def test_application_centos_driver_update_raise_error_if_inb_driver_folder_not_found(self, detect_os,
                                                                                         is_inside_container, create_repo, verify_source, get):
        aota = self._build_aota(cmd='update', app_type='application',
                                uri="http://example.com", device_reboot="Yes")
        self.assertRaises(AotaError, aota.run)
  


    @patch('dispatcher.aota.application_command.get', return_value=Result(200, "ok"))
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("", "", 0))
    @patch('dispatcher.aota.factory.detect_os', return_value='CentOS')
    def test_application_centos_driver_update_raise_error_if_file_is_not_rpm_type(self, detect_os, run, get):
        aota = self._build_aota(cmd='update', app_type='application', uri="https://example.com/sample/sample.deb")
        with self.assertRaisesRegex(AotaError, "Invalid file type"):
            aota.run()


    @patch('dispatcher.aota.application_command.CentOsApplication.is_rpm_file_type', return_value=True)
    @patch('inbm_common_lib.shell_runner.PseudoShellRunner.run', return_value=("", "", 0))
    @patch('dispatcher.aota.application_command.Application.identify_package', return_value=SupportedDriver.XLINK.value)
    @patch('dispatcher.aota.application_command.move_file')
    @patch('os.listdir', return_value=[])
    @patch('dispatcher.aota.aota_command.AotaCommand.create_repository_cache_repo')
    @patch('dispatcher.aota.factory.is_inside_container', return_value=True, device_reboot="Yes")
    @patch('dispatcher.aota.factory.detect_os', return_value='CentOS')
    def test_application_centos_driver_update_raise_pass(self, detect_os, mock_detect_os, create_repo, listdir, mock_move,
                                                         support_driver, run, mock_is_rpm_file_type):
        aota = self._build_aota(cmd='update', app_type='application', uri="http://example.com")
        self.assertIsNone(aota.run())


if __name__ == '__main__':
    unittest.main()
