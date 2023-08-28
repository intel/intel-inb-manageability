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
    install_requires=['mock', 'pynose', 'packaging',
                      'future', 'paho-mqtt', 'jsonschema', 'cryptography'],
    test_suite='nose.collector',
    tests_require=['pynose']
)
