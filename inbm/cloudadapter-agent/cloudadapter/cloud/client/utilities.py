"""
Utility functions and classes used throughout the cloud.client module


"""
import json
import logging
import re
from datetime import datetime
from ssl import SSLContext, CERT_REQUIRED, PROTOCOL_TLS, OP_NO_TLSv1_1, OP_NO_TLSv1, OP_NO_COMPRESSION, \
    OP_NO_RENEGOTIATION, TLSVersion, OP_NO_SSLv2, OP_NO_SSLv3
from typing import Union, Tuple, Optional, Dict, Any

from future.moves.urllib.request import getproxies

logger = logging.getLogger(__name__)


# ========== Provides proxy endpoint, if given

class ProxyConfig:

    def __init__(self, hostname: str = None, port: int = None) -> None:
        """Construct a proxy configuration object

        @param hostname: (str) Hostname for proxy without http://
        @param port:     (int) Port for proxy
        """
        logger.debug("")
        if hostname and port:
            logger.debug(
                f"Setting up ProxyConfig object with hostname {hostname} port {port}")
            self._endpoint = (hostname, port)
        else:
            logger.debug("Setting up ProxyConfig object with _get_http_proxy()")
            self._endpoint = self._get_http_proxy()

    @property
    def endpoint(self) -> Union[Tuple[str, int], None]:
        """Read-only proxy endpoint property

        @return: (Union[Tuple[str, int], None]) Proxy endpoint if given
        """
        return self._endpoint

    def _get_http_proxy(self) -> Tuple[str, int]:
        """Obtain HTTP proxy information from the given arguments"""
        proxy = getproxies().get("http")

        logger.debug("Independent getproxies_environment call: {}".format(str(getproxies())))

        if proxy:
            logger.debug("Got proxy: {}".format(str(proxy)))
            proxy = proxy.split(':')[1:]  # Ignore 'http'
            endpoint = proxy[0].strip("/")
            port = int(proxy[1].strip("/"))
            proxy = (endpoint, port)
        else:
            logger.debug("Could not get HTTP proxy")

        return proxy


# ========== Provides TLS configuration


class TLSConfig:

    def __init__(self, ca_certs: Optional[str] = None, device_cert: Optional[str] = None,
                 device_key: Optional[str] = None):
        """Construct a TLS configuration

        @param ca_certs: (str) File path to CA certificates to use
        @exception IOError: If CA certificates path is invalid
        """
        self._context = self._make_tls_context(ca_certs, device_cert, device_key)

    @property
    def context(self):
        """Read-only TLS context

        @return: (SSLContext) The TLS context
        """
        return self._context

    def _make_tls_context(self, ca_certs: Optional[str] = None, device_cert: Optional[str] = None,
                          device_key: Optional[str] = None):
        """Create a TLS context from the given arguments"""
        context = SSLContext(protocol=PROTOCOL_TLS)
        # List from Vincent
        cipher = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:' \
                 'ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' \
                 'ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256'
        context.options |= OP_NO_TLSv1_1 | OP_NO_TLSv1 | OP_NO_RENEGOTIATION | OP_NO_COMPRESSION | OP_NO_SSLv2 | OP_NO_SSLv3
        context.set_ciphers(cipher)

        context.minimum_version = TLSVersion.TLSv1_2
        context.verify_mode = CERT_REQUIRED
        context.check_hostname = True

        # NOTE: only device_cert is required, assuming the device_cert file contains both a 
        # device cert and a device key inside it. Normally with ThingsBoard this is the case,
        # and here device_key will be None. load_cert_chain allows None for device_key and will
        # try to load both key/cert from device_cert.
        if device_cert:
            logger.debug(
                f'Loading cert chain. device_cert = {device_cert}, device_key = {device_key}')
            try:
                context.load_cert_chain(device_cert, device_key)
            except OSError:
                raise OSError(f"Invalid device cert/key path")
        if ca_certs:
            try:
                context.load_verify_locations(ca_certs)
            except OSError:
                logger.debug(f"Invalid CA certifications path: {ca_certs}")
                raise OSError(f"Invalid CA certificates path")
        else:
            context.load_default_certs()

        return context


# ========== Outputs a formatted string


class Formatter:

    def __init__(self, formatting, defaults={}):
        """Create a formatter for a given string formatting.
        Placeholder fields are surrounded with brackets,
        and there are no spaces in the bracketed placeholder field.
        Add the raw_ prefix to any variable name to avoid escaping the string.
        For instance: "Hello {name}!" or "Hello {raw_name}!"
        The following placeholders will be given a value by default:
        - {ts}: Integer epoch timestamp in milliseconds
        - {timestamp}: UTC string timestamp
        Additionally, the {timestamp} may be given a specific
        formatting through the syntax: {timestamp=[formatting]}
        where [formatting] is a strftime formatted string, per:
        https://docs.python.org/2/library/datetime.html#strftime-strptime-behavior

        @param formatting: (str) Formatting string
        @param defaults:  (dict) Any constant defaults
        """
        self._formatting = formatting
        self._defaults = defaults
        self._fields = set()  # type: ignore
        fields = re.finditer(r"{([\w\=\:\-\.\%]+)}", self._formatting)
        for f in fields:
            self._fields.add(f.group(1))

    def _escape(self, string):
        """Escape quotes and control characters in the given string

        @param string: (str) String to escape
        @return: (str) Escaped string
        """
        escapes = {
            "\\": "\\\\",
            "\"": "\\\"",
            "\n": "\\n",
            "\r": "\\r",
            "\t": "\\t"
        }
        for target, escape in escapes.items():
            string = string.replace(target, escape)
        return string

    def format(self, time=None, **fields):
        """Format a string with the given mapping

        @param time: (datetime) Override default time
        @param fields: (str) Field name mapped to its given value
        @return: (str) The formatted string
        """
        output = self._formatting
        if time is None:
            time = datetime.utcnow()

        # Update default {ts} and {timestamp}
        self._defaults.update(
            ts=str(int((time - datetime.utcfromtimestamp(0)).total_seconds() * 1000)),
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC"))

        for f in self._fields:
            replacement = None
            field_name = f[4:] if f.startswith("raw_") else f

            if field_name in fields:
                replacement = str(fields[field_name])
                if not f.startswith("raw_"):
                    replacement = self._escape(replacement)
            elif field_name in self._defaults:
                replacement = str(self._defaults[field_name])
            elif "timestamp" in f.split("="):
                time_format = f.split("=")[1]
                replacement = time.strftime(time_format)
            else:
                logger.error("Field {%s} not supplied in: %s", f, self._formatting)
                continue

            output = output.replace("{" + f + "}", replacement)

        return output


# ========== Holds parsed method information


class MethodParsed:

    def __init__(self, method: str = "", args: Dict[str, Any] = {}, **symbols: str):
        """Construct readonly parsed method information
        @param method:    (str) Method name
        @param args:   (dict) Method arguments
        @param symbols: (str) Additionally parsed symbols
        """
        self._method = method
        self._args = args
        self._symbols = symbols

    @property
    def method(self):
        return self._method

    @property
    def args(self):
        return self._args

    @property
    def symbols(self):
        return self._symbols


# ========== Outputs parsed method information


class MethodParser:

    def __init__(self, parse_info, aggregate_info=None):
        """Create a parser to process method information from
        the raw string the topic and payload.
        parse_info is a dict with the following format:
        {
            "field_to_parse_from_topic": {
                "regex": [Regular expression to use],
                "group": [Integer group of given regex]
            },
            "field_to_parse_from_payload": {
                "path": [String path to traverse payload]
            },
            ...
        }
        aggregate_info is a dict with the "path" property,
        pointing to an array of method objects.

        @param parse_info: (dict) Parsing information
        @param aggregate_info: (dict) Aggregate parsing information
        """
        self._parse_info = parse_info
        self._aggregate_info = aggregate_info

    def _parse_by_path(self, obj, path):
        """Parse a value from an object via a path
        Paths are in the form: root/child/...

        @param path: (str) Path to use
        @param obj: (dict) Object to traverse
        @return: (Any) The value parsed, or None if not found
        """
        path = [p for p in path.split("/") if p.strip()]
        value = obj

        for p in path:
            if not isinstance(value, dict):
                return None
            value = value.get(p)

        return value

    def _parse_by_regex(self, raw, regex, group):
        """Parse a value from a raw string via a regex

        @param raw:   (str) Raw string input to parse
        @param regex: (str) Uncompiled regular expression to use
        @param group: (int) Group number of the match to return
        @return: (Any) The value parsed, or None if not found
        """
        match = re.search(regex, raw)
        return match.group(group) if match else None

    def _parse_single(self, topic, payload):
        """Parse a single method

        @param topic:    (str) Raw topic
        @param payload: (dict) Payload in object form
        @return: (MethodParsed) Parsed method information
        @exception TypeError: If there was an unexpected type
        """
        parsed = {}

        for key, parse in self._parse_info.items():
            value = None

            path = parse.get("path")
            if path is not None:
                value = self._parse_by_path(payload, path)
            else:
                regex = parse.get("regex")
                group = parse.get("group")
                value = self._parse_by_regex(topic, regex, group)

            parsed[key] = value

        args = parsed.get("args")
        if not args or not isinstance(args, dict):
            parsed.update(args={})

        method = parsed.get("method")
        if not method or not isinstance(method, str):
            parsed.update(method="")

        return MethodParsed(**parsed)

    def parse(self, topic, payload):
        """Parse a given topic and payload

        @param topic:   (str) Raw topic
        @param payload: (str) Raw payload
        @return: (List[MethodParsed]) All parsed method information
        @exception ValueError: If the input payload was malformed
        """
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, TypeError) as e:
            raise ValueError(str(e))

        if self._aggregate_info:
            parsed = []

            path = self._aggregate_info.get("path")
            payloads = self._parse_by_path(payload, path)
            if payloads:
                for p in payloads:
                    parsed.append(self._parse_single(topic, p))

            return parsed

        return [self._parse_single(topic, payload)]
