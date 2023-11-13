import pytest
from inbc.validator import ConfigurationItem, configuration_bounds_check, validate_guid, validate_package_list
import argparse

@pytest.fixture
def config_item():
    return ConfigurationItem('RegistrationRetry Timer Secs', 1, 60, 20)

def test_return_value_when_within_limits(config_item):
    assert configuration_bounds_check(config_item, 30) == 30

def test_return_default_when_below_lower_limit(config_item):
    assert configuration_bounds_check(config_item, 0) == 20

def test_return_default_when_above_upper_limit(config_item):
    assert configuration_bounds_check(config_item, 61) == 20

def test_return_value_when_on_upper_limit(config_item):
    assert configuration_bounds_check(config_item, 60) == 60

def test_return_value_when_on_lower_limit(config_item):
    assert configuration_bounds_check(config_item, 1) == 1

def test_check_validate_guid_format():
    assert validate_guid('6c8e136f-d3e6-4131-ac32-4687cb4abd27') == '6c8e136f-d3e6-4131-ac32-4687cb4abd27'

@pytest.mark.parametrize("guid,expected", [
    ('6c8e13-d3e6-4131-ac32-4687cb4abd27', 'first 8 characters'),
    ('6c8e136f2b-d3e6-4131-ac32-4687cb4abd27', 'first 8 characters'),
    ('6c8e136f-d3e-4131-ac32-4687cb4abd27', 'second 4 characters'),
    ('6c8e136f-d3e6aa-4131-ac32-4687cb4abd27', 'second 4 characters'),
    ('6c8e136f-d3e6-41-ac32-4687cb4abd27', 'third 4 characters'),
    ('6c8e136f-d3e6-413156-ac32-4687cb4abd27', 'third 4 characters'),
    ('6c8e136f-d3e6-4131-a-4687cb4abd27', 'fourth 4 characters'),
    ('6c8e136f-d3e6-4131-ac32def-4687cb4abd27', 'fourth 4 characters'),
    ('6c8e136f-d3e6-4131-ac32-4687cb4ab', 'fifth 12 characters'),
    ('6c8e136f-d3e6-4131-ac32-4687cb4abd27ef89', 'fifth 12 characters')
])
def test_check_validate_guid_raises_error(guid, expected):
    with pytest.raises(argparse.ArgumentTypeError, match="GUID should be 36 characters displayed in five groups separated by a dash in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX and Hexdigits are allowed"):
        validate_guid(guid)

# List of valid package names
valid_packages = [
    'hello',
    'hello-world',
    'hello.world',
    'hello+world',
    'helloworld123',
    'hello-123.world',
]

# List of invalid package names
invalid_packages = [
    'Hello',
    'hello world',
    '!hello',
    'hello@world',
    'helloworld_123',
    '-hello',
    '.hello',
    '+hello',
]

# Test valid package names
@pytest.mark.parametrize("package", valid_packages)
def test_validate_package_list_valid_packages(package):
    assert validate_package_list(package) == [package]

# Test invalid package names
@pytest.mark.parametrize("package", invalid_packages)
def test_validate_package_list_invalid_packages(package):
    with pytest.raises(argparse.ArgumentTypeError):
        validate_package_list(package)

# Test multiple valid package names combined in a comma-separated string
def test_validate_package_list_multiple_valid_packages():
    package_list = ','.join(valid_packages)
    assert validate_package_list(package_list) == valid_packages

# Test multiple invalid package names combined in a comma-separated string
@pytest.mark.parametrize("package", invalid_packages)
def test_validate_package_list_multiple_invalid_packages(package):
    package_list = ','.join(valid_packages + [package])
    with pytest.raises(argparse.ArgumentTypeError):
        validate_package_list(package_list)