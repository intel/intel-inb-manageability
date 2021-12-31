from setuptools import setup, find_packages
from future import standard_library
standard_library.install_aliases()

with open('README.md') as f:
    readme = f.read()

setup(
    name='telemetry-agent',
    description='IoT telemetry agent',
    long_description=readme,
    license='Intel Proprietary (see \'licenses\' directory)',
    packages=find_packages(exclude=('tests', 'doc')),
    include_package_data=True,
    install_requires=['nose', 'packaging', 'future', 'paho-mqtt', 'psutil'],
    test_suite='nose.collector',
    tests_require=['nose']
)
