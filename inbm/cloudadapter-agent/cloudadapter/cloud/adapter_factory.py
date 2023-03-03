"""
Provides concrete adapters with the Abstract Adapter interface

Copyright (C) 2017-2023 Intel Corporation
SPDX-License-Identifier: Apache-2.0
"""


from .adapters.azure_adapter import AzureAdapter
from .adapters.telit_adapter import TelitAdapter
from .adapters.generic_adapter import GenericAdapter
from ..constants import ADAPTER_CONFIG_PATH
from ..exceptions import BadConfigError
from typing import Dict, List
from .adapters.adapter import Adapter
import json


def load_adapter_config() -> Dict:
    """Loads and parses the adapter configuration file
    @exception BadConfigError: If there was an issue loading the configuration file
    """
    try:
        with open(ADAPTER_CONFIG_PATH) as config_file:
            config_contents = config_file.read()
            return json.loads(config_contents)
    except OSError as e:
        raise BadConfigError(f"Could not load configuration: {e}")
    return {}


def get_adapter_config_filepaths() -> List[str]:
    """Get the file locations of the active adapter's configuration

    @return: (List[str]) The file locations
    """
    adapter_config = load_adapter_config()
    files = adapter_config.get("auxiliary_files", [])
    files.append(ADAPTER_CONFIG_PATH)
    return files


def get_adapter() -> Adapter:
    """Retrieve a preconfigured cloud adapter with the Adapter interface

    @return: (Adapter) A concrete adapter
    @exception BadConfigError: If there was an issue creating the adapter
    """
    adapter_config = load_adapter_config()

    config = adapter_config.get("config", None)
    if config is None:
        raise BadConfigError("No configuration found!")

    cloud = adapter_config.get("cloud", None)

    if cloud == "azure":
        return AzureAdapter(config)
    elif cloud == "telit":
        return TelitAdapter(config)
    elif cloud is not None:
        return GenericAdapter(config)
    else:
        raise BadConfigError("No cloud indicated!")
