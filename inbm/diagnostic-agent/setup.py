from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

setup(
    name='diagnostic-agent',
    version='0.1.2',
    description='IoT Diagnostic Agent',
    long_description=readme,
    license='Intel Proprietary (see \'licenses\' directory)',
    packages=find_packages(exclude=['*.*', 'mqttclient']),
    include_package_data=True,
    install_requires=['mock', 'nose', 'packaging', 'future'],
    test_suite='nose.collector',
    tests_require=['nose']
)
