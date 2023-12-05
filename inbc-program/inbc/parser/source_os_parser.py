"""Source OS Parser class to parse the system argument

   Copyright (C) 2020-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import argparse


def os_add(args: argparse.Namespace) -> str:
    manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type>' \
               '<source type=os><add><repos>'
    for source in args.s.split(','):
        manifest += '<source_pkg>' + source.strip() + '</source_pkg>'
    manifest += '</repos></add></source></manifest>'

    print("manifest {0}".format(manifest))
    return manifest


def os_remove(args: argparse.Namespace) -> str:
    manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type>' \
               '<source type=os><remove><repos>'
    for source in args.s.split(','):
        manifest += '<source_pkg>' + source.strip() + '</source_pkg>'
    manifest += '</repos></remove></source></manifest>'

    print("manifest {0}".format(manifest))
    return manifest


def os_update(args: argparse.Namespace) -> str:
    manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type>' \
               '<source type=os><update><repos>'
    for source in args.s.split(','):
        manifest += '<source_pkg>' + source.strip() + '</source_pkg>'
    manifest += '</repos></update></source></manifest>'

    print("manifest {0}".format(manifest))
    return manifest


def os_list(args: argparse.Namespace) -> str:
    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest><type>source</type>' +
                '<source type=os>' +
                '</list></source>' +
                '</manifest>')

    print("manifest {0}".format(manifest))
    return manifest
