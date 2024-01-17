"""Parser class to parse the system argument

   Copyright (C) 2020-2024 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import argparse

from ..xml_tag import create_xml_tag
from ..utility import _get_password
from ..inbc_exception import InbcException


def load(args: argparse.Namespace) -> str:
    """Creates manifest in XML format.

    @param args: Arguments provided by the user from command line
    @return: Generated xml manifest string
    """

    arguments = {
        'fetch': args.uri,
        'signature': args.signature,
        'username': args.username,
        'password': _get_password(args.username, "Please provide the password: ")
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


def get(args: argparse.Namespace) -> str:
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


def set(args: argparse.Namespace) -> str:
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


def append(args: argparse.Namespace) -> str:
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


def remove(args: argparse.Namespace) -> str:
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
