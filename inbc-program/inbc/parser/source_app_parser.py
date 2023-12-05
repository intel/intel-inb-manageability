"""Source Application Parser class to parse the system argument

   Copyright (C) 2020-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import argparse

from ..xml_tag import create_xml_tag


def application_add(args: argparse.Namespace) -> str:
    arguments = {
        'path': args.gkp,
        'keyname': args.gkn,
        'source': args.s,
        'filename': args.f,
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest>' +
                '<type>source</type>' +
                '<source type=application>' +
                '<application>' +
                '<add><gpg>'
                '{0}' +
                '{1}'
                '</gpg><repo>' +
                '{2}'
                '{3}</repo>'
                '</add></application></source>' +
                '</manifest>').format(create_xml_tag(arguments, "path"),
                                      create_xml_tag(arguments, "keyname"),
                                      create_xml_tag(arguments, "source"),
                                      create_xml_tag(arguments, "filename"))

    print("manifest {0}".format(manifest))
    return manifest


def application_remove(args: argparse.Namespace) -> str:
    arguments = {
        'keyid': args.gki,
        'filename': args.f
    }

    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest><type>source</type>' +
                '<source type=application>' +
                '<application><remove><gpg>'
                '{0}' +
                '</gpg><repo>' +
                '{1}'
                '</repo>'
                '</remove></application></source>' +
                '</manifest>').format(create_xml_tag(arguments, "keyid"),
                                      create_xml_tag(arguments, "filename"))

    print("manifest {0}".format(manifest))
    return manifest


def application_update(args: argparse.Namespace) -> str:
    arguments = {
        'source_pkg': args.s,
        'filename': args.f
    }
    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest><type>source</type>' +
                '<source type=application>' +
                '<application><update><repo>'
                '{0}{1}' +
                '</repo></update></application></source>' +
                '</manifest>').format(create_xml_tag(arguments, "source_pkg"),
                                      create_xml_tag(arguments, "filename"))

    print("manifest {0}".format(manifest))
    return manifest


def application_list(args: argparse.Namespace) -> str:
    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest><type>source</type>' +
                '<source type=application>' +
                '<application></list></application></source>' +
                '</manifest>')

    print("manifest {0}".format(manifest))
    return manifest
