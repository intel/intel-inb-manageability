"""Parser class to parse the system argument

   Copyright (C) 2020-2022 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import logging
import argparse
import getpass

from datetime import datetime
from typing import Any, Optional, Sequence, Tuple
from inbc.xml_tag import create_xml_tag
from inbm_common_lib.dmi import get_dmi_system_info, is_dmi_path_exists
from inbm_common_lib.device_tree import get_device_tree_system_info
from inbm_common_lib.platform_info import PlatformInformation
from inbm_common_lib.validater import validate_date, validate_string_less_than_n_characters
from inbm_common_lib.constants import LOCAL_SOURCE, REMOTE_SOURCE
from inbm_lib.detect_os import detect_os, LinuxDistType
from inbm_vision_lib.constants import TARGET, TARGET_TYPE

from .inbc_exception import InbcException
from .constants import FOTA_SIGNATURE, TARGETS_HELP, TARGETS_NODE_AND_CLIENT_ONLY_HELP, \
    TARGETS_NODE_ONLY_HELP, PATH_STRING

logger = logging.getLogger(__name__)


class ArgsParser(object):
    """Parser class to parse command line parameter."""

    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(
            description='INBC Command-line tool to trigger updates')
        self.subparsers = self.parser.add_subparsers(
            help='valid commands: [fota, sota, pota, load, get, set, restart, query]')

        self.parse_fota_args()
        self.parse_sota_args()
        self.parse_pota_args()
        self.parse_load_args()
        self.parse_get_args()
        self.parse_set_args()
        self.parse_restart_args()
        self.parse_query_args()

    def parse_args(self, args: Optional[Sequence[str]]) -> Any:
        """Gets parsed arguments from user input.

        @param args: parameter entered by user
        """
        return self.parser.parse_args(args)

    def _create_subparser(self, subparser_name: str) -> argparse.ArgumentParser:
        parser = self.subparsers.add_parser(subparser_name)
        parser.add_argument('--nohddl', action='store_true')
        return parser

    @staticmethod
    def _add_source_options(parser: argparse.ArgumentParser):
        source_group = parser.add_mutually_exclusive_group(required=True)
        source_group.add_argument('--uri', '-u',
                                  type=lambda x: validate_string_less_than_n_characters(
                                      x, 'URL', 1000),
                                  help='Remote URI from where to retrieve package')
        source_group.add_argument('--path', '-p', help='Full path to the update package',
                                  type=lambda x: validate_string_less_than_n_characters(x, PATH_STRING, 500))

    @staticmethod
    def _add_pota_source_options(parser: argparse.ArgumentParser):
        source_fota_group = parser.add_mutually_exclusive_group(required=True)
        source_fota_group.add_argument('--fotauri', '-fu',
                                       type=lambda x: validate_string_less_than_n_characters(
                                           x, 'FOTA url', 1000),
                                       help='Remote URI from where to retrieve FOTA package')
        source_fota_group.add_argument('--fotapath', '-fp', help='Full path to the FOTA update package(fip)',
                                       type=lambda x: validate_string_less_than_n_characters(x, 'FOTA path', 500))

    def parse_fota_args(self) -> None:
        """Method to parse FOTA arguments"""
        # Create the parser for the "fota" command
        parser_fota = self._create_subparser('fota')
        ArgsParser._add_source_options(parser_fota)

        parser_fota.add_argument('--releasedate', '-r', default='2024-12-31', required=False, type=validate_date,
                                 help='Release date of the applying package - format YYYY-MM-DD')
        parser_fota.add_argument('--vendor', '-v', default='Intel', required=False, help='Platform vendor',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Vendor', 50))
        parser_fota.add_argument('--biosversion', '-b', default='5.12', required=False, help='Platform BIOS version',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'BIOS Version', 50))
        parser_fota.add_argument('--manufacturer', '-m', default='intel', required=False, help='Platform manufacturer',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Manufacturer', 50))
        parser_fota.add_argument('--product', '-pr', default='kmb-hddl2', required=False, help='Platform product name',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Product', 50))
        parser_fota.add_argument('--signature', '-s', default='None', required=False, help='Signature string',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Signature', 1000))
        parser_fota.add_argument('--tooloptions', '-to', required=False, help='Firmware tool options',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Tool Options', 10))
        parser_fota.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        parser_fota.add_argument('--target', '-t', nargs='*',
                                 default=['None'], required=False, help=TARGETS_HELP)
        parser_fota.set_defaults(func=fota)

    def parse_sota_args(self) -> None:
        """Method to parse SOTA arguments"""
        parser_sota = self._create_subparser('sota')

        parser_sota.add_argument('--uri', '-u', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'URL', 1000),
                                 help='Remote URI from where to retrieve package')
        parser_sota.add_argument('--path', '-p', help='Full path to the update package', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(x, PATH_STRING, 500))
        parser_sota.add_argument('--releasedate', '-r', default='2024-12-31', required=False, type=validate_date,
                                 help='Release date of the applying package - format YYYY-MM-DD')
        parser_sota.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        parser_sota.add_argument('--target', '-t', nargs='*',
                                 default=['None'], required=False, help=TARGETS_HELP)
        parser_sota.set_defaults(func=sota)

    def parse_pota_args(self) -> None:
        """Method to parse POTA arguments."""
        parser_pota = self._create_subparser('pota')
        ArgsParser._add_pota_source_options(parser_pota)

        parser_pota.add_argument('--releasedate', '-r', default='2024-12-31', required=False, type=validate_date,
                                 help='Release date of the applying package - format YYYY-MM-DD')
        parser_pota.add_argument('--vendor', '-v', default='Intel', required=False,
                                 help='Platform vendor')
        parser_pota.add_argument('--biosversion', '-b', default='5.12', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'BIOS Version', 50),
                                 help='Platform BIOS version')
        parser_pota.add_argument('--manufacturer', '-m', default='intel', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'Manufacturer', 50),
                                 help='Platform manufacturer')
        parser_pota.add_argument('--product', '-pr', default='kmb-hddl2', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'Product', 50),
                                 help='Platform product name')
        parser_pota.add_argument('--sotapath', '-sp', default=None, required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'SOTA path', 500),
                                 help='Full path to the update package (mender file)')
        parser_pota.add_argument('--sotauri', '-su', default=None, required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'SOTA path', 500),
                                 help='Full path to the update package')
        parser_pota.add_argument('--release_date', '-sr', default='2024-12-31', required=False, type=validate_date,
                                 help='Release date of the applying mender package - format YYYY-MM-DD')
        parser_pota.add_argument('--fotasignature', '-fs', default='None', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'FOTA Signature', 1000),
                                 help='FOTA Signature string')
        parser_pota.add_argument('--target', '-t', nargs='*',
                                 default=['None'], required=False, help=TARGETS_HELP)
        parser_pota.set_defaults(func=pota)

    def parse_load_args(self) -> None:
        """Parse load arguments"""
        parser_load = self._create_subparser('load')
        ArgsParser._add_source_options(parser_load)

        parser_load.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        parser_load.add_argument('--target', '-t', nargs='*',
                                 default=None, required=False,
                                 help=TARGETS_NODE_AND_CLIENT_ONLY_HELP)

        parser_load.add_argument('--targettype', '-tt', default='node', required=False,
                                 help='Type of target [vision | node | node-client]')
        parser_load.set_defaults(func=load)

    def parse_get_args(self) -> None:
        """Parse get arguments"""
        parser_get = self._create_subparser('get')

        parser_get.add_argument('--path', '-p', required=True,
                                type=lambda x: validate_string_less_than_n_characters(
                                    x, 'Path', 500),
                                help='Full path to key(s)')
        parser_get.add_argument('--target', '-t', nargs='*',
                                default=None, required=False,
                                help=TARGETS_NODE_AND_CLIENT_ONLY_HELP)
        parser_get.add_argument('--targettype', '-tt', default='node', required=False,
                                help='Type of target [vision | node | node-client]')
        parser_get.set_defaults(func=get)

    def parse_set_args(self) -> None:
        """Parse set arguments"""
        parser_set = self._create_subparser('set')

        parser_set.add_argument('--path', '-p', required=True,
                                type=lambda x: validate_string_less_than_n_characters(
                                    x, PATH_STRING, 500),
                                help='Full path to key(s)')
        parser_set.add_argument('--target', '-t', nargs='*',
                                default=None, required=False,
                                help=TARGETS_NODE_AND_CLIENT_ONLY_HELP)
        parser_set.add_argument('--targettype', '-tt', default='node', required=False,
                                help='Type of target [vision | node | node-client]')
        parser_set.set_defaults(func=set)

    def parse_restart_args(self) -> None:
        """Parse restart arguments"""
        parser_restart = self._create_subparser('restart')

        parser_restart.add_argument('--target', '-t', nargs='*', default=None, required=False,
                                    help=TARGETS_NODE_ONLY_HELP)
        parser_restart.add_argument('--targettype', '-tt', default='node', required=False,
                                    help='Type of target [vision | node ]')
        parser_restart.set_defaults(func=restart)

    def parse_query_args(self) -> None:
        """Parse set arguments"""
        parser_query = self._create_subparser('query')

        parser_query.add_argument('--target', '-t', nargs='*', default=None, required=False,
                                  help=TARGETS_NODE_ONLY_HELP)
        parser_query.add_argument('--targettype', '-tt', default=None, required=False,
                                  help='Type of target [vision | node ]')
        parser_query.add_argument('--option', '-o', default='all', required=False,
                                  choices=['all', 'hw', 'fw', 'os',
                                           'status', 'version', 'security', 'guid', 'swbom'],
                                  help='Type of information [all | hw | fw | os | status (for vision-agent only) | security | guid (for vision-agent only) '
                                       'version | swbom(for inbm only) ]')
        parser_query.set_defaults(func=query)


def _create_source(args) -> Tuple[str, str, str]:
    repo = LOCAL_SOURCE if not args.nohddl else REMOTE_SOURCE
    if repo == LOCAL_SOURCE and args.path is None:
        raise InbcException('local path (-p) is required with HDDL command.')
    if repo == REMOTE_SOURCE and args.uri is None:
        raise InbcException('URI (-u) is required with non-HDDL command')

    source_tag = PATH_STRING if repo == LOCAL_SOURCE else 'fetch'
    source_location = args.path if repo == LOCAL_SOURCE else args.uri
    return repo, source_tag, source_location


def _get_password(args) -> Optional[str]:
    password = None
    if args.nohddl and args.username:
        password = getpass.getpass("Please provide the password: ")
    return password


def sota(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """
    print(f'nohddl={args.nohddl}, path={args.path}')
    if not args.nohddl and not args.path:
        raise InbcException('argument --path/-p: required with HDDL command.')

    if args.nohddl and not args.uri:
        # Update on local Ubuntu system.  Does update through ubuntu without fetching a package.
        repo, source_tag, source_location = REMOTE_SOURCE, PATH_STRING, None
    else:
        repo, source_tag, source_location = _create_source(args)

    # if source_location is None, then update is local Ubuntu and does not need a release date.
    release_date = args.releasedate if source_location else None

    # This if clause is necessary to have the fetch/path xml tags placed in sequence to comply with the xsd sxhema.
    if source_tag == PATH_STRING:
        path_location = source_location
        fetch_location = None
    else:
        fetch_location = source_location
        path_location = None

    arguments = {
        'Target': args.target,
        'fetch': fetch_location,
        'nohddl': args.nohddl,
        'username': args.username,
        'password': _get_password(args),
        'release_date': release_date,
        'path': path_location
    }

    target_type = '<targetType>node</targetType>' if not args.nohddl else ''
    repo_tag = '<repo>' + repo + '</repo>' if repo else ''
    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>ota</type>' +
                '<ota>' +
                '<header>' +
                '<type>sota</type>' +
                repo_tag +
                '</header>' +
                '<type><sota>' +
                '<cmd logtofile="y">update</cmd>' +
                target_type +
                '{0}' +
                '</sota></type>' +
                '</ota>' +
                '</manifest>').format(
        create_xml_tag(arguments,
                       "Target",
                       "fetch",
                       "username",
                       "password",
                       "release_date",
                       "path"
                       )
    )
    print("manifest {0}".format(manifest))
    return manifest


def _gather_system_details() -> PlatformInformation:
    print("Biosversion, Vendor, Manufacturer and Product information not provided via command-line."
          " So gathering the firmware info using dmi path/deviceTree")

    if is_dmi_path_exists():
        print("DMI path exists. Getting BIOS information from DMI path")
        platform_information = get_dmi_system_info()
        if platform_information:
            return platform_information

    return get_device_tree_system_info()


def fota(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated XML manifest string
    """
    repo, source_tag, source_location = _create_source(args)

    if args.nohddl:
        p = _gather_system_details()

    arguments = {
        'releasedate': args.releasedate,
        'vendor': p.bios_vendor if args.nohddl else args.vendor,
        'biosversion': p.bios_version if args.nohddl else args.biosversion,
        'manufacturer': p.platform_mfg if args.nohddl else args.manufacturer,
        'product': p.platform_product if args.nohddl else args.product,
        'Target': args.target,
        'signature': args.signature,
        'repo': repo,
        'tooloptions': args.tooloptions,
        source_tag: source_location,
        'nohddl': args.nohddl,
        'username': args.username,
        'password': _get_password(args)
    }

    target_type = '<targetType>node</targetType>' if not args.nohddl else ''
    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>ota</type>' +
                '<ota>' +
                '<header>' +
                '<type>fota</type>' +
                '<repo>' + repo + '</repo>' +
                '</header>' +
                '<type><fota name="sample">' +
                target_type +
                '{0}</fota></type></ota>' +
                '</manifest>').format(
        create_xml_tag(arguments,
                       "Target",
                       "signature",
                       "biosversion",
                       "vendor",
                       "manufacturer",
                       "product",
                       "releasedate",
                       "tooloptions",
                       "username",
                       "password",
                       source_tag)
    )
    print("manifest {0}".format(manifest))
    return manifest


def pota(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """
    target_type = '<targetType>node</targetType>' if not args.nohddl else ''
    os_type = detect_os()

    if args.fotapath:
        if args.nohddl and os_type == LinuxDistType.Ubuntu.name:
            raise InbcException(
                "POTA is not supported with local 'path' tags on non HDDL Ubuntu device.")
        if not args.sotapath:
            raise InbcException(
                "POTA requires 'fotauri, sotauri' args while using remote URIs and  'fotapath, sotapath' args while using path tags.")
        repo = 'local'
    elif args.fotauri:
        if os_type != LinuxDistType.Ubuntu.name and not args.sotauri:
            raise InbcException(
                "POTA requires 'fotauri, sotauri' args while using remote URIs and  'fotapath, sotapath' args while using path tags.")
        repo = 'remote'

    arguments = {
        'releasedate': args.releasedate,
        'vendor': args.vendor,
        'biosversion': args.biosversion,
        'manufacturer': args.manufacturer,
        'product': args.product,
        'release_date': args.releasedate,
        'Target': args.target,
        FOTA_SIGNATURE: args.fotasignature,
        'nohddl': args.nohddl
    }

    if repo == "local":
        fota_tag = f'<path>{args.fotapath}</path>'
        sota_tag = f'<path>{args.sotapath}</path>'
    else:
        fota_tag = f'<fetch>{args.fotauri}</fetch>'
        sota_tag = '' if os_type == LinuxDistType.Ubuntu.name else f'<fetch>{args.sotauri}</fetch>'

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>ota</type>' +
                '<ota>' +
                '<header><type>pota</type><repo>' + repo + '</repo></header>' +
                '<type>' +
                '<pota>' + target_type +
                '{0}' +
                '<fota name="sample">{1}{2}</fota>' +
                '<sota><cmd logtofile="y">update</cmd>{3}{4}</sota>' +
                '</pota></type></ota>' +
                '</manifest>').format(
        create_xml_tag(arguments,
                       "Target"),
        create_xml_tag(arguments,
                       FOTA_SIGNATURE,
                       "biosversion",
                       "manufacturer",
                       "product",
                       "vendor",
                       "releasedate"
                       ),
        fota_tag,
        create_xml_tag(arguments,
                       "release_date"
                       ),
        sota_tag
    )

    print("manifest {0}".format(manifest))
    return manifest


def load(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """

    if args.nohddl:
        raise InbcException('Load command is only supported for HDDL.')

    arguments = {
        'target': args.target,
        'targetType': args.targettype,
        'path': args.path,
        'nohddl': args.nohddl,
        'username': args.username,
        'password': _get_password(args)
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>config</type>' +
                '<config>' +
                '<cmd>load</cmd>' +
                '{0}' +
                '<configtype>' +
                '{1}' +
                '<load>' +
                '{2}' +
                '</load>' +
                '</configtype>' +
                '</config>' +
                '</manifest>').format(
        create_xml_tag(arguments, "targetType"),
        create_xml_tag(arguments, "target"),
        create_xml_tag(arguments, "path")
    )
    print("manifest {0}".format(manifest))
    return manifest


def get(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """

    arguments = {
        'target': args.target,
        'targetType': None if args.nohddl else args.targettype,
        'path': args.path,
        'nohddl': args.nohddl
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>config</type>' +
                '<config>' +
                '<cmd>get_element</cmd>' +
                '{0}' +
                '<configtype>' +
                '{1}' +
                '<get>' +
                '{2}' +
                '</get>' +
                '</configtype>' +
                '</config>' +
                '</manifest>').format(
        create_xml_tag(arguments, "targetType"),
        create_xml_tag(arguments, "target"),
        create_xml_tag(arguments, "path")
    )
    print("manifest {0}".format(manifest))
    return manifest


def set(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """

    arguments = {
        'target': args.target,
        'targetType': None if args.nohddl else args.targettype,
        'path': args.path,
        'nohddl': args.nohddl
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>config</type>' +
                '<config>' +
                '<cmd>set_element</cmd>' +
                '{0}' +
                '<configtype>' +
                '{1}' +
                '<set>' +
                '{2}' +
                '</set>' +
                '</configtype>' +
                '</config>' +
                '</manifest>').format(
        create_xml_tag(arguments, "targetType"),
        create_xml_tag(arguments, "target"),
        create_xml_tag(arguments, "path")
    )
    print("manifest {0}".format(manifest))
    return manifest


def restart(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """
    if args.nohddl:
        raise InbcException('Restart command is only supported for HDDL.')

    arguments = {
        'target': args.target,
        'targetType': args.targettype,
        'nohddl': args.nohddl
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>cmd</type>' +
                '<cmd>restart</cmd>' +
                '<restart>' +
                '{0}' +
                '{1}' +
                '</restart>' +
                '</manifest>').format(
        create_xml_tag(arguments, TARGET_TYPE),
        create_xml_tag(arguments, TARGET)
    )
    print("manifest {0}".format(manifest))
    return manifest


def query(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """
    arguments = {
        'option': args.option,
        'target': args.target,
        'targetType': args.targettype if args.option != "version" else None,
        'nohddl': args.nohddl
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>cmd</type>' +
                '<cmd>query</cmd>' +
                '<query>' +
                '{0}' +
                '{1}' +
                '{2}' +
                '</query>' +
                '</manifest>').format(
        create_xml_tag(arguments, "option"),
        create_xml_tag(arguments, TARGET_TYPE),
        create_xml_tag(arguments, TARGET)
    )
    print("manifest {0}".format(manifest))
    return manifest
