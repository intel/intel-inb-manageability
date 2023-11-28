from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

setup(
    name='telemetry-agent',
    description='IoT telemetry agent',
    long_description=readme,
    license='Apache 2.0',
    packages=find_packages(exclude=('tests', 'doc')),
    include_package_data=True,
    install_requires=['pytest', 'pytest-cov', 'pytest-mock',
                      'packaging', 'future', 'paho-mqtt', 'psutil'],
    test_suite='pytest',
    tests_require=['pytest', 'pytest-cov', 'pytest-mock']
)
