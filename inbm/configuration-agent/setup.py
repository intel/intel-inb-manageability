from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

setup(
    name='configuration-agent',
    version='0.1.1',
    description='IoT configuration agent',
    long_description=readme,
    license='Intel Proprietary (see \'licenses\' directory)',
    packages=find_packages(exclude=['*.*', 'mqttclient']),
    include_package_data=True,
    install_requires=['pytest', 'pytest-cov', 'pytest-mock', 'packaging', 'future'],
    test_suite='pytest',
    tests_require=['pytest', 'pytest-cov', 'pytest-mock'])
