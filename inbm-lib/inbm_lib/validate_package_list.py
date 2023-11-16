import re
from typing import Optional


def parse_and_validate_package_list(package_list: str) -> Optional[list[str]]:
    """Function to parse and validate the comma-separated package list and return it as a list.
    @param package_list: A comma-separated string of package names (or "")
    @return: A list containing the validated package names ([] if input is ""), or None if validation error
    """
    if package_list == "":
        return []

    package_name_regex = re.compile(r'^[a-z0-9][a-z0-9.+-]*$')

    packages = package_list.split(',')

    for package in packages:
        if not package_name_regex.match(package):
            return None

    return packages
