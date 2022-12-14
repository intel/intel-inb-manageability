import atheris
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

import logging
from abc import ABC

import os
from typing import Dict, Union, Any

with atheris.instrument_imports():
 from unittest import TestCase
@atheris.instrument_func
#from command_pattern import DeviceBatteryHealthChecker