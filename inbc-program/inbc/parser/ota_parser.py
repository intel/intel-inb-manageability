"""Parser class to parse the system argument

   Copyright (C) 2020-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import argparse

from inbm_lib.detect_os import detect_os, LinuxDistType
from inbm_common_lib.dmi import get_dmi_system_info, is_dmi_path_exists
from inbm_common_lib.device_tree import get_device_tree_system_info
from inbm_common_lib.platform_info import PlatformInformation

from ..utility import _get_password
from ..xml_tag import create_xml_tag
from ..constants import FOTA_SIGNATURE, PATH_STRING
from ..inbc_exception import InbcException


def sota(args: argparse.Namespace) -> str:
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

    # pass comma-separated package list as is in manifest
    package_list = args.package_list if args.package_list else ""

    # This is necessary to have the fetch/path xml tags placed in sequence to comply with the xsd schema.
    if source_tag == PATH_STRING:
        path_location = source_location
        fetch_location = None
    else:
        fetch_location = source_location
        path_location = None

    arguments = {
        'mode': args.mode,
        'release_date': release_date,
        'fetch': fetch_location,
        'username': args.username,
        'password': _get_password(args.username, "Please provide the password: "),
        'deviceReboot': "no" if args.mode == "download-only" else args.reboot,
        'path': path_location,
        'package_list': package_list,
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
        (create_xml_tag(arguments,
                        "mode",
                        "package_list",
                        "fetch",
                        "username",
                        "password",
                        "release_date",
                        "path",
                        "deviceReboot"
                        ))
    )
    print("manifest {0}".format(manifest))
    return manifest


def fota(args: argparse.Namespace) -> str:
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
        'password': _get_password(args.username, "Please provide the password: "),
        'guid': args.guid,
        'deviceReboot': args.reboot
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
                       'fetch',
                       "deviceReboot")
    )
    print("manifest {0}".format(manifest))
    return manifest


def pota(args: argparse.Namespace) -> str:
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
        'vendor': p.bios_vendor,
        'biosversion': p.bios_version,
        'manufacturer': p.platform_mfg,
        'product': p.platform_product,
        'release_date': args.release_date,
        FOTA_SIGNATURE: args.fotasignature,
        'guid': args.guid,
        'deviceReboot': args.reboot
    }

    fota_tag = f'<fetch>{args.fotauri}</fetch>'
    sota_tag = '' if os_type == LinuxDistType.Ubuntu.name else f'<fetch>{args.sotauri}</fetch>' \
                                                               f'<deviceReboot>{args.reboot}</deviceReboot>'

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
                       "guid",
                       'deviceReboot'
                       ),
        fota_tag,
        create_xml_tag(arguments,
                       "release_date"
                       ),
        sota_tag
    )

    print("manifest {0}".format(manifest))
    return manifest


def aota(args: argparse.Namespace) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated XML manifest string
    """
    arguments = {
        'cmd': args.command,
        'app': args.app,
        'fetch': args.uri,
        'deviceReboot': args.reboot,
        'username': args.username,
        'password': _get_password(args.username, "Please provide the password: "),
        'version': args.version,
        'containerTag': args.containertag,
        'file': args.file,
        'dockerUsername': args.dockerusername,
        'dockerRegistry': args.dockerregistry,
        'dockerPassword': _get_password(args.dockerusername, "Please provide the docker password: ")
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>ota</type>' +
                '<ota>' +
                '<header>' +
                '<type>aota</type>' +
                '<repo>remote</repo>' +
                '</header>' +
                '<type><aota>' +
                '{0}' +
                '</aota></type>' +
                '</ota>' +
                '</manifest>').format(
        create_xml_tag(arguments,
                       "cmd",
                       "app",
                       "fetch",
                       "deviceReboot",
                       "username",
                       "password",
                       "version",
                       "containerTag",
                       "file",
                       "dockerUsername",
                       "dockerPassword",
                       "dockerRegistry")
    )
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
