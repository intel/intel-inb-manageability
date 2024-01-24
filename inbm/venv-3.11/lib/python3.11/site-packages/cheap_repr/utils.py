import traceback

from sys import version_info

try:
    from qualname import qualname
except ImportError:
    def qualname(cls):
        return cls.__qualname__

PY2 = version_info[0] == 2
PY3 = not PY2

if PY2:
    def viewitems(d):
        return d.viewitems()
else:
    def viewitems(d):
        return d.items()


def safe_qualname(cls):
    # type: (type) -> str
    result = _safe_qualname_cache.get(cls)
    if not result:
        try:
            result = qualname(cls)
        except (AttributeError, IOError, SyntaxError):
            result = cls.__name__
        if '<locals>' not in result:
            _safe_qualname_cache[cls] = result
    return result


_safe_qualname_cache = {}


def type_name(x):
    return safe_qualname(x.__class__)


def exception_string(exc):
    assert isinstance(exc, BaseException)
    return ''.join(traceback.format_exception_only(type(exc), exc)).strip()
