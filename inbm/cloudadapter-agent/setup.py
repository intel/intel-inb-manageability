# Copyright (C) 2017-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

setup(
    name='cloudadapter-agent',
    version='0.1.1',
    description='IoT Cloud Adapter agent',
    long_description=readme,
    license='Intel Proprietary (see \'licenses\' directory)',
    packages=find_packages(exclude=['*.*', 'mqttclient']),
    include_package_data=True,
    install_requires=['nose', 'packaging', 'future'],
    test_suite='nose.collector',
    tests_require=['nose'])
