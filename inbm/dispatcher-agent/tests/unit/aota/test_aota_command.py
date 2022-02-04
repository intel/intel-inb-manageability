from unittest import TestCase

from unit.common.mock_resources import *

from dispatcher.aota.aota_command import Docker, DockerCompose
from dispatcher.aota.application_command import Application
from dispatcher.packagemanager.memory_repo import MemoryRepo


class TestAotaCommand(TestCase):
    @staticmethod
    def _build_mock_repo(num_files=0):
        mem_repo = MemoryRepo('test')

        if num_files != 0:
            for i in range(0, num_files):
                mem_repo.add('test' + str(i + 1) + '.rpm', b'0123456789')
        return mem_repo

    @staticmethod
    def _build_parsed_manifest(num_files=0, signature=None, container_tag=None, uri=None, cmd=None,
                               app_type=None, need_repo=True, file=None,
                               username=None, password=None, docker_registry=None, docker_username=None,
                               docker_password=None):
        hash_algorithm = None

        if need_repo:
            parsed_manifest = {'signature': signature, 'config_params': None, 'version': None,
                               'hash_algorithm': hash_algorithm,
                               'container_tag': container_tag, 'uri': uri,
                               'file': file,
                               'cmd': cmd, 'repo': TestAotaCommand._build_mock_repo(num_files),
                               'app_type': app_type,
                               'username': username, 'password': password,
                               'docker_registry': docker_registry,
                               'docker_username': docker_username,
                               'docker_password': docker_password,
                               'device_reboot': None}
        else:
            parsed_manifest = {'signature': signature, 'config_params': None, 'version': None,
                               'hash_algorithm': hash_algorithm,
                               'container_tag': container_tag, 'uri': uri,
                               'file': file,
                               'cmd': cmd, 'app_type': app_type, 'username': username,
                               'password': password,
                               'docker_registry': docker_registry,
                               'docker_username': docker_username,
                               'docker_password': docker_password,
                               'device_reboot': None}
        return parsed_manifest

    @staticmethod
    def _build_aota(num_files=0, signature=None, container_tag=None, uri=None, cmd=None,
                    app_type=None, need_repo=True, file=None,
                    username=None, password=None, docker_registry=None, docker_username=None,
                    docker_password=None):

        parsed_manifest = TestAotaCommand._build_parsed_manifest(num_files=num_files, signature=signature,
                                                                 container_tag=container_tag,
                                                                 uri=uri, cmd=cmd, app_type=app_type,
                                                                 need_repo=need_repo, file=file,
                                                                 username=username, password=password,
                                                                 docker_registry=docker_registry,
                                                                 docker_username=docker_username,
                                                                 docker_password=docker_password)
        if app_type == 'compose':
            return DockerCompose(MockDispatcherCallbacks.build_mock_dispatcher_callbacks(),
                                 parsed_manifest=parsed_manifest,
                                 dbs=ConfigDbs.ON)
        elif app_type == 'docker':
            return Docker(MockDispatcherCallbacks.build_mock_dispatcher_callbacks(),
                          parsed_manifest=parsed_manifest,
                          dbs=ConfigDbs.ON)
        elif app_type == 'application':
            return Application(MockDispatcherCallbacks.build_mock_dispatcher_callbacks(),
                               parsed_manifest=parsed_manifest,
                               dbs=ConfigDbs.ON)
