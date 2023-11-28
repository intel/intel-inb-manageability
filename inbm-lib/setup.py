from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

test_deps = ['mock==4.0.2', 'types-mock==5.1.0.3', 'pytest==7.4.3', 'testtools==2.5.0', 'ddt==1.2.1']
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
    install_requires=['paho-mqtt==1.5.1', 'dmidecode==0.9.0', 'xmlschema==1.5.3', 'defusedxml==0.7.1', 'future==0.18.3', 'url-normalize==1.4.3', 'snoop==0.4.3'],
    test_suite='pytest',
    tests_require=test_deps,
    extras_require=extras,
    package_data = { 'inbm_lib': ['py.typed'], 'inbm_common_lib': ['py.typed']}
)
