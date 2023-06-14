from typing import Optional

from inbm_common_lib.version import read_version, read_commit
from inbm_lib.constants import INBM_VERSION_FILE, INBM_VISION_VERSION_FILE_HOST, INBM_VISION_VERSION_FILE_NODE


def _read_inbm_version_file() -> Optional[str]:
    try:
        version_file = open(INBM_VERSION_FILE, "r")
        return version_file.read()
    except OSError:
        return None


def _read_inbm_vision_version_file_host() -> Optional[str]:
    try:
        version_file = open(INBM_VISION_VERSION_FILE_HOST, "r")
        return version_file.read()
    except OSError:
        return None


def _read_inbm_vision_version_file_node() -> Optional[str]:
    try:
        version_file = open(INBM_VISION_VERSION_FILE_NODE, "r")
        return version_file.read()
    except OSError:
        return None


def get_inbm_version() -> Optional[str]:
    """Get INBM version from version file
    @return: version string, or None if unable
    """
    contents = _read_inbm_version_file()
    if contents is None:
        return None
    return read_version(contents)


def get_inbm_commit() -> Optional[str]:
    """Get INBM commit from version file
    @return: version string, or None if unable
    """
    contents = _read_inbm_version_file()
    if contents is None:
        return None
    return read_commit(contents)


def get_friendly_inbm_version_commit() -> str:
    """Get a friendly version/commit string for inbm"""

    version = get_inbm_version()
    commit = get_inbm_commit()

    version_str = ""
    if version is None:
        version_str = "unknown version"
    else:
        version_str = version

    commit_str = ""
    if commit is None:
        commit_str = "unknown commit"
    else:
        commit_str = commit

    return f"Intel(R) Manageability version {version_str} ({commit_str})"


def get_inbm_vision_host_version() -> Optional[str]:
    """Get INBM Vision Host version from version file
    @return: version string, or None if unable
    """
    contents = _read_inbm_vision_version_file_host()
    if contents is None:
        return None
    return read_version(contents)


def get_inbm_vision_host_commit() -> Optional[str]:
    """Get INBM vision host commit from version file
    @return: version string, or None if unable
    """
    contents = _read_inbm_vision_version_file_host()
    if contents is None:
        return None
    return read_commit(contents)


def get_inbm_vision_node_version() -> Optional[str]:
    """Get INBM Vision Node version from version file
    @return: version string, or None if unable
    """
    contents = _read_inbm_vision_version_file_node()
    if contents is None:
        return None
    return read_version(contents)


def get_inbm_vision_node_commit() -> Optional[str]:
    """Get INBM vision node commit from version file
    @return: version string, or None if unable
    """
    contents = _read_inbm_vision_version_file_node()
    if contents is None:
        return None
    return read_commit(contents)


def get_friendly_inbm_vision_version_commit() -> str:
    """Get a friendly version/commit string for inbm vision"""

    version = get_inbm_vision_host_version()
    commit = get_inbm_vision_host_commit()
    type = "host"
    if version is None:
        version = get_inbm_vision_node_version()
        commit = get_inbm_vision_node_commit()
        type = "node"

    version_str = ""
    if version is None:
        version_str = "unknown version"
    else:
        version_str = version

    commit_str = ""
    if commit is None:
        commit_str = "unknown commit"
    else:
        commit_str = commit

    return f"Intel(R) Manageability Vision {type} version {version_str} ({commit_str})"
