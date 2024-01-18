"""Source Application Parser class to parse the system argument

   Copyright (C) 2020-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import argparse
import logging

from ..inbc_exception import InbcException
from ..xml_tag import create_xml_tag
from inbm_common_lib.utility import clean_input

logger = logging.getLogger(__name__)


def application_add(args: argparse.Namespace) -> str:
    if bool(args.gpgKeyUri) != bool(args.gpgKeyName):
        raise InbcException(
            "Source requires either both gpgKeyUri and gpgKeyName to be provided, or neither of them.")

    arguments = {
        'uri': args.gpgKeyUri,
        'keyname': args.gpgKeyName,
        'sources': args.sources,
        'filename': args.filename,
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>source</type>' +
                '<applicationSource>' + '<add>')

    if args.gpgKeyUri and args.gpgKeyName:
        manifest += ('<gpg>' + '{0}' + '{1}' + '</gpg>').format(create_xml_tag(arguments, "uri"),
                                                                create_xml_tag(arguments, "keyname"))

    manifest += '<repo><repos>'

    source_tags = (f'<source_pkg>{clean_input(source)}</source_pkg>' for source in args.sources)
    manifest += ''.join(source_tags)

    manifest += ('</repos>'
                 f'{create_xml_tag(arguments, "filename")}</repo>'
                 '</add></applicationSource>' +
                 '</manifest>')

    print("manifest {0}".format(manifest))
    return manifest


def application_remove(args: argparse.Namespace) -> str:
    arguments = {
        'keyname': args.gpgKeyName,
        'filename': args.filename
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest><type>source</type>' +
                '<applicationSource>' +
                '<remove>')

    if args.gpgKeyName:
        manifest += f'<gpg>{create_xml_tag(arguments, "keyname")}</gpg>'

    manifest += ('<repo>' +
                 f'{create_xml_tag(arguments, "filename")}'
                 '</repo>'
                 '</remove></applicationSource>' +
                 '</manifest>')

    print(f"manifest {manifest}")
    return manifest


def application_update(args: argparse.Namespace) -> str:
    arguments = {
        'sources': args.sources,
        'filename': args.filename
    }
    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest><type>source</type>' +
                '<applicationSource>' +
                '<update><repo><repos>')

    for source in args.sources:
        manifest += '<source_pkg>' + clean_input(source.strip()) + '</source_pkg>'

    manifest += (f'</repos>{create_xml_tag(arguments, "filename")}' +
                 '</repo></update></applicationSource>' +
                 '</manifest>')

    print(f"manifest {manifest}")
    return manifest


def application_list(args: argparse.Namespace) -> str:
    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest><type>source</type>' +
                '<applicationSource>' +
                '<list/></applicationSource></manifest>')

    print("manifest {0}".format(manifest))
    return manifest
