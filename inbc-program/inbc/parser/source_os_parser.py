"""Source OS Parser class to parse the system argument

   Copyright (C) 2020-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
"""
import argparse


def os_add(args: argparse.Namespace) -> str:
    manifest = "manifest"

    print("manifest {0}".format(manifest))
    return manifest


def os_remove(args: argparse.Namespace) -> str:
    manifest = "manifest"

    print("manifest {0}".format(manifest))
    return manifest


def os_update(args: argparse.Namespace) -> str:
    manifest = "manifest"

    print("manifest {0}".format(manifest))
    return manifest


def os_list(args: argparse.Namespace) -> str:
    manifest = ('<?xml version="1.0" encoding="utf-8"?>' +
                '<manifest><type>source</type>' +
                '<source type=os>' +
                '<os></list></os></source>' +
                '</manifest>')

    print("manifest {0}".format(manifest))
    return manifest
