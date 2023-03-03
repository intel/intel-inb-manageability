"""
    URI utilities

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import posixpath
from typing import Optional
from urllib.parse import urlsplit, unquote, urlparse

logger = logging.getLogger(__name__)


def is_valid_uri(uri: Optional[str]) -> bool:
    """Check if a URI is valid.

    @param uri: The URI to check
    @return: True if valid, False otherwise
    """

    logger.debug("Attempting to validate URI: " + repr(uri))
    if not uri:
        return False
    return urlparse(uri).scheme in ['http', 'https', 'file', 'ftp']


def uri_to_filename(uri: str) -> str:
    """Return the basename of the uri

    For example: http://www.google.com/c/b/a.txt -> a.txt

    @param uri: the URI to check
    @return basename of the URI"""

    urlpath = urlsplit(uri).path
    return posixpath.basename(unquote(urlpath))


def get_uri_prefix(uri: str) -> str:
    """Return the prefix of the uri

    For example: http://www.google.com/c/b/a.txt -> http://www.google.com/

    @param uri: the URI to check
    @return blank string if there is no scheme (e.g. http) or netloc in the URI."""

    split = urlsplit(uri)
    if split.scheme != "" and split.netloc != "":
        return split.scheme + "://" + split.netloc + "/"
    else:
        return ""
