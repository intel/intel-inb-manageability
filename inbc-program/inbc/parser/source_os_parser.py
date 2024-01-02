"""Source OS Parser class to parse the system argument

   Copyright (C) 2020-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import argparse


def os_add(args: argparse.Namespace) -> str:
    manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type>' \
               '<osSource><add><repos>'
    for source in args.sources:
        manifest += '<source_pkg>' + source.strip() + '</source_pkg>'
    manifest += '</repos></add></osSource></manifest>'

    print("manifest {0}".format(manifest))
    return manifest


def os_remove(args: argparse.Namespace) -> str:
    manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type>' \
               '<osSource><remove><repos>'
    for source in args.sources:
        manifest += '<source_pkg>' + source.strip() + '</source_pkg>'
    manifest += '</repos></remove></osSource></manifest>'

    print("manifest {0}".format(manifest))
    return manifest


def os_update(args: argparse.Namespace) -> str:
    manifest = '<?xml version="1.0" encoding="utf-8"?><manifest><type>source</type>' \
               '<osSource><update><repos>'
    for source in args.sources:
        manifest += '<source_pkg>' + source.strip() + '</source_pkg>'
    manifest += '</repos></update></osSource></manifest>'

    print("manifest {0}".format(manifest))
    return manifest


def os_list(args: argparse.Namespace) -> str:
    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest><type>source</type>' +
                '<osSource>' +
                '<list/></osSource>' +
                '</manifest>')

    print("manifest {0}".format(manifest))
    return manifest
