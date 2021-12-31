# dummy chardet

from typing import Dict

__version__ = '3.0.4'


def detect(content: str) -> Dict[str, str]:
    return {'encoding': 'utf-8'}
