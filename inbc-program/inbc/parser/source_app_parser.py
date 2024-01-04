"""Source Application Parser class to parse the system argument

   Copyright (C) 2020-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import argparse

from ..xml_tag import create_xml_tag


def application_add(args: argparse.Namespace) -> str:
    arguments = {
        'uri': args.gpgKeyUri,
        'keyname': args.gpgKeyName,
        'sources': args.sources,
        'filename': args.filename,
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>source</type>' +
                '<applicationSource>' +
                '<add><gpg>'
                '{0}' +
                '{1}'
                '</gpg><repo><repos>').format(create_xml_tag(arguments, "uri"),
                                              create_xml_tag(arguments, "keyname"))

    for source in args.sources:
        manifest += '<source_pkg>' + source.strip() + '</source_pkg>'

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
                '<remove><gpg>'
                f'{create_xml_tag(arguments, "keyname")}' +
                '</gpg><repo>' +
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
        manifest += '<source_pkg>' + source.strip() + '</source_pkg>'

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
