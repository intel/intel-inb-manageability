from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

setup(
    name='dispatcher-agent',
    description='IoT manageability agent',
    long_description=readme,
    license='Intel Proprietary (see \'licenses\' directory)',
    packages=find_packages(exclude=['tests.*', '*.tests.*', 'tests', '*.tests', 'test_*']),
    include_package_data=True,
    install_requires=['mock', 'pytest', 'pytest-cov', 'pytest-mock', 'packaging',
                      'paho-mqtt', 'jsonschema', 'cryptography'],
    test_suite='pytest',
    tests_require=['pytest', 'pytest-cov', 'pytest-mock']
)
