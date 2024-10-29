from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

test_deps = ['pytest==7.4.3', 'testtools==2.5.0', 'ddt==1.2.1']
extras = {
    'test': test_deps,
}

setup(
    name='inbm-lib',
    description='IoT manageability library',
    long_description=readme,
    license='Intel Proprietary',
    packages=['inbm_lib', 'inbm_common_lib'],
    include_package_data=True,
    install_requires=['paho-mqtt==2.1.0', 'types-paho-mqtt==1.6.0.20240321', 'xmlschema==3.4.2', 'defusedxml==0.7.1', 'url-normalize==1.4.3', 'snoop==0.6.0', 'types-setuptools==75.2.0.20241025', 'jsonschema==4.23.0', 'types-jsonschema==4.23.0.20240813'],
    test_suite='pytest',
    tests_require=test_deps,
    extras_require=extras,
    package_data = { 'inbm_lib': ['py.typed'], 'inbm_common_lib': ['py.typed']}
)
