"""Parser class to parse the system argument

   Copyright (C) 2020-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import logging
import argparse
import getpass

from typing import Any, Optional, Sequence
from inbc.xml_tag import create_xml_tag
from inbm_common_lib.dmi import get_dmi_system_info, is_dmi_path_exists
from inbm_common_lib.device_tree import get_device_tree_system_info
from inbm_common_lib.platform_info import PlatformInformation
from inbm_common_lib.validater import validate_date, validate_string_less_than_n_characters, validate_guid
from inbm_lib.detect_os import detect_os, LinuxDistType

from .inbc_exception import InbcException
from .constants import FOTA_SIGNATURE, PATH_STRING

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
        self.parse_append_args()
        self.parse_remove_args()
        self.parse_restart_args()
        self.parse_query_args()

    def parse_args(self, args: Optional[Sequence[str]]) -> Any:
        """Gets parsed arguments from user input.

        @param args: parameter entered by user
        """
        return self.parser.parse_args(args)

    def _create_subparser(self, subparser_name: str) -> argparse.ArgumentParser:
        return self.subparsers.add_parser(subparser_name)

    def parse_fota_args(self) -> None:
        """Method to parse FOTA arguments"""
        # Create the parser for the "fota" command
        parser_fota = self._create_subparser('fota')

        parser_fota.add_argument('--uri', '-u', required=True,
                                 type=lambda x: validate_string_less_than_n_characters(x, 'URL', 1000),
                                 help='Remote URI from where to retrieve package')
        parser_fota.add_argument('--releasedate', '-r', default='2026-12-31', required=False, type=validate_date,
                                 help='Release date of the applying package - format YYYY-MM-DD')
        parser_fota.add_argument('--signature', '-s', default='None', required=False, help='Signature string',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Signature', 1000))
        parser_fota.add_argument('--tooloptions', '-to', required=False, help='Firmware tool options',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Tool Options', 10))
        parser_fota.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        parser_fota.add_argument('--guid', '-gu', required=False, help='Firmware guid update',
                                 type=validate_guid)
        parser_fota.set_defaults(func=fota)

    def parse_sota_args(self) -> None:
        """Method to parse SOTA arguments"""
        parser_sota = self._create_subparser('sota')

        parser_sota.add_argument('--uri', '-u', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'URL', 1000),
                                 help='Remote URI from where to retrieve package')
        parser_sota.add_argument('--releasedate', '-r', default='2026-12-31', required=False, type=validate_date,
                                 help='Release date of the applying package - format YYYY-MM-DD')
        parser_sota.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        parser_sota.set_defaults(func=sota)

    def parse_pota_args(self) -> None:
        """Method to parse POTA arguments."""
        parser_pota = self._create_subparser('pota')

        parser_pota.add_argument('--fotauri', '-fu', required=True,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'FOTA url', 1000),
                                 help='Remote URI from where to retrieve FOTA package')
        parser_pota.add_argument('--releasedate', '-r', default='2026-12-31', required=False, type=validate_date,
                                 help='Release date of the applying package - format YYYY-MM-DD')
        parser_pota.add_argument('--sotauri', '-su', default=None, required=True,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'SOTA path', 500),
                                 help='Full path to the update package')
        parser_pota.add_argument('--release_date', '-sr', default='2026-12-31', required=False, type=validate_date,
                                 help='Release date of the applying mender package - format YYYY-MM-DD')
        parser_pota.add_argument('--fotasignature', '-fs', default='None', required=False,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'FOTA Signature', 1000),
                                 help='FOTA Signature string')
        parser_pota.add_argument('--guid', '-gu', required=False, help='Firmware GUID update',
                                 type=validate_guid)
        parser_pota.set_defaults(func=pota)

    def parse_load_args(self) -> None:
        """Parse load arguments"""
        parser_load = self._create_subparser('load')

        parser_load.add_argument('--uri', '-u', required=True,
                                 type=lambda x: validate_string_less_than_n_characters(
                                     x, 'URL', 1000),
                                 help='Remote URI from where to retrieve package')
        parser_load.add_argument('--username', '-un', required=False, help='Username on the remote server',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Username', 50))
        parser_load.add_argument('--signature', '-s', default='None', required=False, help='Signature string',
                                 type=lambda x: validate_string_less_than_n_characters(x, 'Signature', 1000))
        parser_load.set_defaults(func=load)

    def parse_get_args(self) -> None:
        """Parse get arguments"""
        parser_get = self._create_subparser('get')

        parser_get.add_argument('--path', '-p', required=True,
                                type=lambda x: validate_string_less_than_n_characters(
                                    x, 'Path', 500),
                                help='Full path to key(s)')
        parser_get.set_defaults(func=get)

    def parse_set_args(self) -> None:
        """Parse set arguments"""
        parser_set = self._create_subparser('set')

        parser_set.add_argument('--path', '-p', required=True,
                                type=lambda x: validate_string_less_than_n_characters(
                                    x, PATH_STRING, 500),
                                help='Full path to key(s)')
        parser_set.set_defaults(func=set)

    def parse_remove_args(self) -> None:
        """Parse remove arguments"""
        parser_remove = self._create_subparser('remove')

        parser_remove.add_argument('--path', '-p', required=True,
                                   type=lambda x: validate_string_less_than_n_characters(
                                       x, 'Path', 500),
                                   help='Full path to key(s)')
        parser_remove.set_defaults(func=remove)

    def parse_append_args(self) -> None:
        """Parse append arguments"""
        parser_append = self._create_subparser('append')

        parser_append.add_argument('--path', '-p', required=True,
                                   type=lambda x: validate_string_less_than_n_characters(
                                       x, 'Path', 500),
                                   help='Full path to key(s)')
        parser_append.set_defaults(func=append)

    def parse_restart_args(self) -> None:
        """Parse restart arguments"""
        parser_restart = self._create_subparser('restart')
        parser_restart.set_defaults(func=restart)

    def parse_query_args(self) -> None:
        """Parse set arguments"""
        parser_query = self._create_subparser('query')
        parser_query.add_argument('--option', '-o', default='all', required=False,
                                  choices=['all', 'hw', 'fw', 'os', 'version', 'swbom'],
                                  help='Type of information [all | hw | fw | os | version | swbom ]')
        parser_query.set_defaults(func=query)


def _get_password(args) -> Optional[str]:
    password = None
    if args.username:
        password = getpass.getpass("Please provide the password: ")
    return password


def sota(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated XML manifest string
    """
    if not args.uri:
        # Update on local Ubuntu system.  Does update through ubuntu without fetching a package.
        source_tag, source_location = PATH_STRING, None
    else:
        source_tag, source_location = 'fetch', args.uri

    # if source_location is None, then update is local Ubuntu and does not need a release date.
    release_date = args.releasedate if source_location else None

    # This is necessary to have the fetch/path xml tags placed in sequence to comply with the xsd schema.
    if source_tag == PATH_STRING:
        path_location = source_location
        fetch_location = None
    else:
        fetch_location = source_location
        path_location = None

    arguments = {
        'release_date': release_date,
        'fetch': fetch_location,
        'username': args.username,
        'password': _get_password(args),
        'path': path_location
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>ota</type>' +
                '<ota>' +
                '<header>' +
                '<type>sota</type>' +
                '<repo>remote</repo>' +
                '</header>' +
                '<type><sota>' +
                '<cmd logtofile="y">update</cmd>' +
                '{0}' +
                '</sota></type>' +
                '</ota>' +
                '</manifest>').format(
        create_xml_tag(arguments,
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
    print("BIOS version, Vendor, Manufacturer and Product information will be automatically "
          "gathered using DMI path/deviceTree.")

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

    p = _gather_system_details()

    arguments = {
        'releasedate': args.releasedate,
        'vendor': p.bios_vendor,
        'biosversion': p.bios_version,
        'manufacturer': p.platform_mfg,
        'product': p.platform_product,
        'signature': args.signature,
        'tooloptions': args.tooloptions,
        'fetch': args.uri,
        'username': args.username,
        'password': _get_password(args),
        'guid': args.guid
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>ota</type>' +
                '<ota>' +
                '<header>' +
                '<type>fota</type>' +
                '<repo>remote</repo>' +
                '</header>' +
                '<type><fota name="sample">' +
                '{0}</fota></type></ota>' +
                '</manifest>').format(
        create_xml_tag(arguments,
                       "signature",
                       "biosversion",
                       "vendor",
                       "manufacturer",
                       "product",
                       "releasedate",
                       "tooloptions",
                       "username",
                       "password",
                       "guid",
                       'fetch')
    )
    print("manifest {0}".format(manifest))
    return manifest


def pota(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """
    os_type = detect_os()
    p = _gather_system_details()

    if args.fotauri:
        if os_type != LinuxDistType.Ubuntu.name and not args.sotauri:
            raise InbcException(
                "POTA requires 'fotauri, sotauri' args while using remote URIs.")

    arguments = {
        'releasedate': args.releasedate,
        'vendor': p.vendor,
        'biosversion': p.biosversion,
        'manufacturer': p.manufacturer,
        'product': p.product,
        'release_date': args.release_date,
        FOTA_SIGNATURE: args.fotasignature,
        'guid': args.guid
    }

    fota_tag = f'<fetch>{args.fotauri}</fetch>'
    sota_tag = '' if os_type == LinuxDistType.Ubuntu.name else f'<fetch>{args.sotauri}</fetch>'

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>ota</type>' +
                '<ota>' +
                '<header><type>pota</type><repo>remote</repo></header>' +
                '<type>' +
                '<pota>' +
                '<fota name="sample">{0}{1}</fota>' +
                '<sota><cmd logtofile="y">update</cmd>{2}{3}</sota>' +
                '</pota></type></ota>' +
                '</manifest>').format(
        create_xml_tag(arguments,
                       FOTA_SIGNATURE,
                       "biosversion",
                       "manufacturer",
                       "product",
                       "vendor",
                       "releasedate",
                       "guid"
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

    arguments = {
        'fetch': args.uri,
        'signature': args.signature,
        'username': args.username,
        'password': _get_password(args)
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>config</type>' +
                '<config>' +
                '<cmd>load</cmd>' +
                '<configtype>' +
                '<load>' +
                '{0}' +
                '{1}' +
                '{2}' +
                '</load>' +
                '</configtype>' +
                '</config>' +
                '</manifest>').format(
        create_xml_tag(arguments, "path"),
        create_xml_tag(arguments, "fetch"),
        create_xml_tag(arguments, "signature")
    )
    print("manifest {0}".format(manifest))
    return manifest


def get(args) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """

    arguments = {
        'path': args.path
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>config</type>' +
                '<config>' +
                '<cmd>get_element</cmd>' +
                '<configtype>' +
                '<get>' +
                '{0}' +
                '</get>' +
                '</configtype>' +
                '</config>' +
                '</manifest>').format(
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
        'path': args.path
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>config</type>' +
                '<config>' +
                '<cmd>set_element</cmd>' +
                '<configtype>' +
                '<set>' +
                '{0}' +
                '</set>' +
                '</configtype>' +
                '</config>' +
                '</manifest>').format(
        create_xml_tag(arguments, "path")
    )
    print("manifest {0}".format(manifest))
    return manifest


def append(args) -> str:
    """Creates manifest in XML format.
    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """
    if not args.path:
        raise InbcException('argument --path/-p: required.')

    arguments = {
        'path': args.path
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>config</type>' +
                '<config>' +
                '<cmd>append</cmd>' +
                '<configtype>' +
                '<append>' +
                '{0}'
                '</append>' +
                '</configtype>' +
                '</config>' +
                '</manifest>').format(
        create_xml_tag(arguments, "path")
    )
    print("manifest {0}".format(manifest))
    return manifest


def remove(args) -> str:
    """Creates manifest in XML format.
    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """
    if not args.path:
        raise InbcException('argument --path/-p: required .')

    arguments = {
        'path': args.path
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>config</type>' +
                '<config>' +
                '<cmd>remove</cmd>' +
                '<configtype>' +
                '<remove>' +
                '{0}'
                '</remove>' +
                '</configtype>' +
                '</config>' +
                '</manifest>').format(
        create_xml_tag(arguments, "path")
    )
    print("manifest {0}".format(manifest))
    return manifest


def restart(args) -> str:
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


def query(args) -> str:
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
