from inbm_lib.validate_package_list import validate_package_list

def test_validate_package_list_empty_string():
    assert validate_package_list("") == []

def test_validate_package_list_single_valid_package():
    package_list = "package"
    expected = ["package"]
    assert validate_package_list(package_list) == expected

def test_validate_package_list_multiple_valid_packages():
    package_list = "package1,package2,package3"
    expected = ["package1", "package2", "package3"]
    assert validate_package_list(package_list) == expected

def test_validate_package_list_with_invalid_package():
    package_list = "package1,INVALID-package,@badname"
    assert validate_package_list(package_list) is None

def test_validate_package_list_with_whitespace():
    package_list = " package1 , package2 , package3 "    
    assert validate_package_list(package_list) is None

def test_validate_package_list_with_empty_elements():
    package_list = ",,package1, package2, , , package3,,"
    assert validate_package_list(package_list) is None

def test_validate_package_list_with_special_characters():
    package_list = "package.name, package+plus, package-version"
    expected = ["package.name", "package+plus", "package-version"]
    assert validate_package_list(package_list) is None