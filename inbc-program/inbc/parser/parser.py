"""Parser class to parse the system argument

   Copyright (C) 2020-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import logging
import argparse

from typing import Any, Optional, Sequence

from .config_parser import load, get, set, append, remove
from .ota_parser import fota, sota, pota, aota
from .source_app_parser import application_add, application_remove, application_update, application_list
from .source_os_parser import os_add, os_remove, os_update, os_list
from ..inbc_exception import InbcException
from ..xml_tag import create_xml_tag
from ..constants import PATH_STRING
from ..validator import validate_date, validate_string_less_than_n_characters, validate_guid, validate_package_list

logger = logging.getLogger(__name__)


class ArgsParser(object):
    """Parser class to parse command line parameter."""

    def __init__(self) -> None:
        self.main_parser = argparse.ArgumentParser(
            description='INBC Command-line tool to trigger updates')
        self.inbc_subparsers = self.main_parser.add_subparsers(help='valid commands: [aota, fota, sota, pota, '
                                                                    'load, get, set, restart, query, source]')

        self.parse_aota_args()
        self.parse_fota_args()
        self.parse_sota_args()
        self.parse_pota_args()
        self.parse_load_args()
        self.parse_get_args()
        self.parse_set_args()
        self.parse_append_args()
        self.parse_remove_args()
        self.parse_restart_args()
        self.parse_query_args()
        self.parse_source_args()

    def parse_args(self, args: Optional[Sequence[str]]) -> Any:
        """Gets parsed arguments from user input.

        @param args: parameter entered by user
        """
        return self.main_parser.parse_args(args)

    def parse_source_args(self) -> None:
        source_parser = self.inbc_subparsers.add_parser(
            'source', help='Manage source configurations')
        source_subparsers = source_parser.add_subparsers(
            help='valid source types: [application, os]')
        source_subparsers.required = True
        source_parser.set_defaults(func=lambda args: source_parser.print_help())

        # Application Sub-level
        application_parser = source_subparsers.add_parser('application')
        app_subparsers = application_parser.add_subparsers(
            help='valid commands: [add, remove, update, list]')
        app_subparsers.required = True

        # Application Add Command
        app_add_parser = app_subparsers.add_parser('add')
        app_add_parser.add_argument('--gpgKeyUri', '-gku', required=True,
                                    type=lambda x: validate_string_less_than_n_characters(
                                        x, 'str', 1500),
                                    help='Uri from which to download GPG key')
        app_add_parser.add_argument('--gpgKeyName', '-gkn', required=True,
                                    type=lambda x: validate_string_less_than_n_characters(
                                        x, 'str', 200),
                                    help='Name to store the GPG key information')
        app_add_parser.add_argument('--sources', '-s', required=True, nargs="*", default=[],
                                    type=lambda x: validate_string_less_than_n_characters(
                                        x, 'List[str]', 3500),
                                    help='List of source information to store in the file')
        app_add_parser.add_argument('--filename', '-f', required=True,
                                    type=lambda x: validate_string_less_than_n_characters(
                                        x, 'str', 200),
                                    help='file name to use when storing the source information')
        app_add_parser.set_defaults(func=application_add)

        # Application Remove Command
        app_remove_parser = app_subparsers.add_parser('remove')
        app_remove_parser.add_argument('--gpgKeyName', '--gkn', required=True,
                                       type=lambda x: validate_string_less_than_n_characters(
                                           x, 'str', 50),
                                       help='GPG key name of the source to remove.')
        app_remove_parser.add_argument('--filename', '-f', required=True,
                                       type=lambda x: validate_string_less_than_n_characters(
                                           x, 'str', 200),
                                       help='file name to use when storing the source information')
        app_remove_parser.set_defaults(func=application_remove)

        # Application Update Command
        app_update_parser = app_subparsers.add_parser('update')
        app_update_parser.add_argument('--filename', '-f', required=True,
                                       type=lambda x: validate_string_less_than_n_characters(
                                           x, 'str', 200),
                                       help='file name to use when storing the source information')
        app_update_parser.add_argument('--sources', '-s', required=True, nargs="*", default=[],
                                       type=lambda x: validate_string_less_than_n_characters(
                                           x, 'List[str]', 3500),
                                       help='List of source information to store in the file')
        app_update_parser.set_defaults(func=application_update)

        # Application List Command
        app_list_parser = app_subparsers.add_parser('list')
        app_list_parser.set_defaults(func=application_list)

        # OS Sub-level
        os_parser = source_subparsers.add_parser('os')
        os_subparsers = os_parser.add_subparsers(
            help='valid commands: [add, remove, update, list]')
        os_subparsers.required = True

        # OS Add Command
        os_add_parser = os_subparsers.add_parser('add')
        os_add_parser.add_argument('--sources', '-s', required=True, nargs="*", default=[],
                                   type=lambda x: validate_string_less_than_n_characters(
                                       x, 'List[str]', 3500),
                                   help='List of source information to store in the file')
        os_add_parser.set_defaults(func=os_add)

        # OS Remove Command
        os_remove_parser = os_subparsers.add_parser('remove')
        os_remove_parser.add_argument('--sources', '-s', required=True, nargs="*", default=[],
                                      type=lambda x: validate_string_less_than_n_characters(
                                          x, 'List[str]', 3500),
                                      help='Source information to remove from the file')
        os_remove_parser.set_defaults(func=os_remove)

        # OS Update Command
        os_update_parser = os_subparsers.add_parser('update')
        os_update_parser.add_argument('--sources', '-s', required=True, nargs="*", default=[],
                                      type=lambda x: validate_string_less_than_n_characters(
                                          x, 'List[str]', 3500),
                                      help='Source information to replace in the file')
        os_update_parser.set_defaults(func=os_update)

        # OS List Command
        os_list_parser = os_subparsers.add_parser('list')
        os_list_parser.set_defaults(func=os_list)

    def parse_aota_args(self) -> None:
        """Method to parse AOTA arguments"""
        aota_parser = self.inbc_subparsers.add_parser('aota')

        aota_parser.add_argument('--uri', '-u', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'URL', 1000),
                                 help='Remote URI from where to retrieve package')
        aota_parser.add_argument('--app', '-a', required=True, choices=['application', 'compose', 'docker'],
                                 help='Type of information [application, compose, docker]')
        aota_parser.add_argument('--command', '-c', required=True,
                                 choices=['update', 'pull', 'up',
                                          'down', 'import', 'load', 'remove'],
                                 help='Type of information [ update , pull, up, down, import, load, remove]')
        aota_parser.add_argument('--reboot', '-rb', default='no', required=False, choices=['yes', 'no'],
                                 help='Type of information [ yes | no ]')
        aota_parser.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        aota_parser.add_argument('--version', '-v', required=False)
        aota_parser.add_argument('--containertag', '-ct', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'TAG', 50),
                                 help='Container Tag name')
        aota_parser.add_argument('--file', '-f', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'FILE', 100),
                                 help='File name')
        aota_parser.add_argument('--dockerusername', '-du', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'Docker Username', 50),
                                 help='docker username')
        aota_parser.add_argument('--dockerregistry', '-dr', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'Docker Registry', 500),
                                 help='docker registry')
        aota_parser.set_defaults(func=aota)

    def parse_fota_args(self) -> None:
        """Method to parse FOTA arguments"""
        # Create the parser for the "fota" command
        parser_fota = self.inbc_subparsers.add_parser('fota')

        parser_fota.add_argument('--uri', '-u', required=True,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'URL', 1000),
                                 help='Remote URI from where to retrieve package')
        parser_fota.add_argument('--releasedate', '-r', default='2026-12-31', required=False, type=validate_date,
                                 help='Release date of the applying package - format YYYY-MM-DD')
        parser_fota.add_argument('--signature', '-s', default='None', required=False, help='Signature string',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Signature', 1000))
        parser_fota.add_argument('--tooloptions', '-to', required=False, help='Firmware tool options',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Tool Options', 10))
        parser_fota.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        parser_fota.add_argument('--reboot', '-rb', default='yes', required=False, choices=['yes', 'no'],
                                 help='Type of information [ yes | no ]')
        parser_fota.add_argument('--guid', '-gu', required=False, help='Firmware guid update',
                                 type=validate_guid)
        parser_fota.set_defaults(func=fota)

    def parse_sota_args(self) -> None:
        """Method to parse SOTA arguments"""
        parser_sota = self.inbc_subparsers.add_parser('sota')

        parser_sota.add_argument('--uri', '-u', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'URL', 1000),
                                 help='Remote URI from where to retrieve package')
        parser_sota.add_argument('--releasedate', '-r', default='2026-12-31', required=False, type=validate_date,
                                 help='Release date of the applying package - format YYYY-MM-DD')
        parser_sota.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        parser_sota.add_argument('--reboot', '-rb', default='yes', required=False, choices=['yes', 'no'],
                                 help='Type of information [ yes | no ]')
        parser_sota.add_argument('--mode', '-m', default='full',
                                 required=False, choices=['full', 'download-only', 'no-download'])
        parser_sota.add_argument('--package-list', '-p', required=False,
                                 type=lambda x: validate_package_list(x),
                                 help='Comma-separated list of package names to install')
        parser_sota.set_defaults(func=sota)

    def parse_pota_args(self) -> None:
        """Method to parse POTA arguments."""
        pota_parser = self.inbc_subparsers.add_parser('pota')

        pota_parser.add_argument('--fotauri', '-fu', required=True,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'FOTA url', 1000),
                                 help='Remote URI from where to retrieve FOTA package')
        pota_parser.add_argument('--releasedate', '-r', default='2026-12-31', required=False, type=validate_date,
                                 help='Release date of the applying package - format YYYY-MM-DD')
        pota_parser.add_argument('--sotauri', '-su', default=None, required=True,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'SOTA path', 500),
                                 help='Full path to the update package')
        pota_parser.add_argument('--release_date', '-sr', default='2026-12-31', required=False, type=validate_date,
                                 help='Release date of the applying mender package - format YYYY-MM-DD')
        pota_parser.add_argument('--fotasignature', '-fs', default='None', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'FOTA Signature', 1000),
                                 help='FOTA Signature string')
        pota_parser.add_argument('--guid', '-gu', required=False, help='Firmware GUID update',
                                 type=validate_guid)
        pota_parser.add_argument('--reboot', '-rb', default='yes', required=False, choices=['yes', 'no'],
                                 help='Type of information [ yes | no ]')
        pota_parser.set_defaults(func=pota)

    def parse_load_args(self) -> None:
        """Parse load arguments"""
        load_parser = self.inbc_subparsers.add_parser('load')

        load_parser.add_argument('--uri', '-u', required=True,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'URL', 1000),
                                 help='Remote URI from where to retrieve package')
        load_parser.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        load_parser.add_argument('--signature', '-s', default='None', required=False, help='Signature string',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Signature', 1000))
        load_parser.set_defaults(func=load)

    def parse_get_args(self) -> None:
        """Parse get arguments"""
        config_get_parser = self.inbc_subparsers.add_parser('get')

        config_get_parser.add_argument('--path', '-p', required=True,
                                       type=lambda x: validate_string_less_than_n_characters(
                                           x, 'Path', 500),
                                       help='Full path to key(s)')
        config_get_parser.set_defaults(func=get)

    def parse_set_args(self) -> None:
        """Parse set arguments"""
        config_set_parser = self.inbc_subparsers.add_parser('set')

        config_set_parser.add_argument('--path', '-p', required=True,
                                       type=lambda x: validate_string_less_than_n_characters(
                                           x, PATH_STRING, 500),
                                       help='Full path to key(s)')
        config_set_parser.set_defaults(func=set)

    def parse_remove_args(self) -> None:
        """Parse remove arguments"""
        config_remove_parser = self.inbc_subparsers.add_parser('remove')

        config_remove_parser.add_argument('--path', '-p', required=True,
                                          type=lambda x: validate_string_less_than_n_characters(
                                              x, 'Path', 500),
                                          help='Full path to key(s)')
        config_remove_parser.set_defaults(func=remove)

    def parse_append_args(self) -> None:
        """Parse append arguments"""
        config_append_parser = self.inbc_subparsers.add_parser('append')

        config_append_parser.add_argument('--path', '-p', required=True,
                                          type=lambda x: validate_string_less_than_n_characters(
                                              x, 'Path', 500),
                                          help='Full path to key(s)')
        config_append_parser.set_defaults(func=append)

    def parse_restart_args(self) -> None:
        """Parse restart arguments"""
        restart_parser = self.inbc_subparsers.add_parser('restart')
        restart_parser.set_defaults(func=restart)

    def parse_query_args(self) -> None:
        """Parse set arguments"""
        query_parser = self.inbc_subparsers.add_parser('query')
        query_parser.add_argument('--option', '-o', default='all', required=False,
                                  choices=['all', 'hw', 'fw', 'os', 'version', 'swbom'],
                                  help='Type of information [all | hw | fw | os | version | swbom ]')
        query_parser.set_defaults(func=query)


def restart(args: argparse.Namespace) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """
    raise InbcException('Restart command is not supported.')

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>cmd</type>' +
                '<cmd>restart</cmd>' +
                '<restart>' +
                '</restart>' +
                '</manifest>')
    print("manifest {0}".format(manifest))
    return manifest


def query(args: argparse.Namespace) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """
    arguments = {
        'option': args.option
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>cmd</type>' +
                '<cmd>query</cmd>' +
                '<query>' +
                '{0}' +
                '</query>' +
                '</manifest>').format(
        create_xml_tag(arguments, "option")
    )
    print("manifest {0}".format(manifest))
    return manifest
