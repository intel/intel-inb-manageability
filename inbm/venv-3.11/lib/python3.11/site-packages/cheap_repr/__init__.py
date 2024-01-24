"""
MIT License

Copyright (c) 2021 Alex Hall

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import inspect
import warnings
from array import array
from collections import defaultdict, deque
from importlib import import_module
from itertools import islice, repeat

from cheap_repr.utils import type_name, exception_string, safe_qualname, viewitems, PY2, PY3

if PY2:
    from itertools import izip as zip, izip_longest as zip_longest
    from collections import Mapping, Set
else:
    from itertools import zip_longest
    from collections.abc import Mapping, Set


try:
    from .version import __version__
except ImportError:  # pragma: no cover
    # version.py is auto-generated with the git tag when building
    __version__ = "???"


class ReprSuppressedWarning(Warning):
    """
    This warning is raised when a class is supressed from having a
    repr calculated for it by cheap_repr in the future.
    Instead the output will be of the form:
    <MyClass instance at 0x123 (repr suppressed)>
    This can happen when either:
    1. An exception is raised by either repr(x) or f(x) where
       f is a registered repr function for that class. See
       'Exceptions in repr functions' in the README for more.
    2. The output of repr(x) is longer than
       cheap_repr.suppression_threshold characters.
    """


repr_registry = {}


def try_register_repr(module_name, class_name):
    """
    This tries to register a repr function for a class that may not exist,
    e.g. if the class is in a third party package that may not be installed.
    module_name and class_name are strings. If the class can be imported,
    then:

        @try_register_repr(module_name, class_name)
        def repr_function(...)
            ...

    is equivalent to:

        from <module_name> import <class_name>
        @register_repr(<class_name>)
        def repr_function(...)
            ...

    If the class cannot be imported, nothing happens.
    """
    try:
        cls = getattr(import_module(module_name), class_name)
        return register_repr(cls)
    except Exception:
        return lambda x: x


def register_repr(cls):
    """
    Register a repr function for cls. The function must accept two arguments:
    the object to be represented as a string, and an instance of ReprHelper.
    The registered function will be used by cheap_repr when appropriate,
    and can be retrieved by find_repr_function(cls).
    """

    assert inspect.isclass(cls), 'register_repr must be called with a class. ' \
                                 'The type of %s is %s' % (cheap_repr(cls), type_name(cls))

    def decorator(func):
        repr_registry[cls] = func
        func.__dict__.setdefault('maxparts', 6)
        return func

    return decorator


def maxparts(num):
    """
    See the maxparts section in the README.
    """

    def decorator(func):
        func.maxparts = num
        return func

    return decorator


@try_register_repr('pandas.core.internals', 'BlockManager')
def basic_repr(x, *_):
    return '<%s instance at %#x>' % (type_name(x), id(x))


@try_register_repr('importlib.machinery', 'ModuleSpec')
@register_repr(type(register_repr))
@register_repr(type(_ for _ in []))
@register_repr(type(inspect))
def normal_repr(x, *_):
    """
    Register this with a class to indicate that its own
    __repr__ method is already fine. This prevents it from
    being supressed when its output is a bit long.
    """
    return repr(x)


suppressed_classes = set()


@register_repr(object)
@maxparts(60)
def repr_object(x, helper):
    s = repr(x)
    if type(x).__repr__ is object.__repr__:
        return s

    if len(s) > cheap_repr.suppression_threshold:
        cls = x.__class__
        suppressed_classes.add(cls)
        warnings.warn(ReprSuppressedWarning(
            '%s.__repr__ is too long and has been suppressed. '
            'Register a repr for the class to avoid this warning '
            'and see an informative repr again, '
            'or increase cheap_repr.suppression_threshold' % safe_qualname(cls)))
    return helper.truncate(s)


def find_repr_function(cls):
    for cls in inspect.getmro(cls):
        func = repr_registry.get(cls)
        if func:
            return func


__raise_exceptions_from_default_repr = False


def raise_exceptions_from_default_repr():
    global __raise_exceptions_from_default_repr
    __raise_exceptions_from_default_repr = True
    repr_object.raise_exceptions = True


def cheap_repr(x, level=None, target_length=None):
    """
    Return a short, computationally inexpensive string
    representation of x, with approximately up to `level`
    levels of nesting.
    """
    if level is None:
        level = cheap_repr.max_level
    x_cls = getattr(x, '__class__', type(x))
    for cls in inspect.getmro(x_cls):
        if cls in suppressed_classes:
            return _basic_but('repr suppressed', x)
        func = repr_registry.get(cls)
        if func:
            helper = ReprHelper(level, func, target_length)
            return _try_repr(func, x, helper)

    # Old-style classes in Python 2.
    return _try_repr(repr, x)


cheap_repr.suppression_threshold = 300
cheap_repr.raise_exceptions = False
cheap_repr.max_level = 3


def _try_repr(func, x, *args):
    try:
        return func(x, *args)
    except BaseException as e:
        should_raise = (cheap_repr.raise_exceptions or
                        getattr(func, 'raise_exceptions', False) or
                        func is repr and __raise_exceptions_from_default_repr)
        if should_raise:
            raise
        cls = x.__class__
        if cls not in suppressed_classes:
            suppressed_classes.add(cls)
            warnings.warn(ReprSuppressedWarning(
                "Exception '%s' in %s for object of type %s. "
                "The repr has been suppressed for this type." %
                (exception_string(e), func.__name__, safe_qualname(cls))))
        return _basic_but('exception in repr', x)


def _basic_but(message, x):
    return '%s (%s)>' % (basic_repr(x)[:-1], message)


class ReprHelper(object):
    __slots__ = ('level', 'func', 'target_length')

    def __init__(self, level, func, target_length):
        self.level = level
        self.func = func
        self.target_length = target_length

    def repr_iterable(self, iterable, left, right, end=False, length=None):
        """
        Produces a comma-separated representation of `iterable`, automatically handling nesting and iterables
        that are too long, surrounded by `left` and `right`.
        The number of items is at most `maxparts` (see the configuration section in the README).

        Set `end=True` to include items from both the beginning and end, possibly leaving out items
        in the middle. Only do this if `iterable` supports efficient slicing at the end, e.g. `iterable[-3:]`.

        Provide the `length` parameter if `len(iterable)` doesn't work. Usually this is not needed.
        """

        if length is None:
            length = len(iterable)
        if self.level <= 0 and length:
            s = '...'
        else:
            newlevel = self.level - 1
            max_parts = original_maxparts = self.func.maxparts
            truncate = length > max_parts
            target_length = self.target_length

            if target_length is None or not truncate:
                if end and truncate:
                    # Round up from half, e.g. 7 -> 4
                    max_parts -= max_parts // 2

                pieces = [cheap_repr(elem, newlevel) for elem in islice(iterable, max_parts)]

                if truncate:
                    pieces.append('...')

                    if end:
                        max_parts = original_maxparts - max_parts

                        pieces += [cheap_repr(elem, newlevel) for elem in iterable[-max_parts:]]

            else:
                pieces = []
                right_pieces = []
                total_length = 3 + len(left) + len(right)

                if end:
                    sentinel = object()

                    def parts_gen():
                        for left_part, right_part in zip_longest(
                                iterable[:length - length // 2],
                                islice(reversed(iterable), length // 2),
                                fillvalue=sentinel,
                        ):
                            yield left_part, pieces
                            if right_part is not sentinel:
                                yield right_part, right_pieces

                    parts = parts_gen()
                else:
                    parts = zip(iterable, repeat(pieces))

                for i, (part, pieces_list) in enumerate(parts):
                    r = cheap_repr(part, newlevel)
                    pieces_list.append(r)
                    total_length += len(r) + 2
                    if max_parts <= i + 1 < length and total_length >= target_length:
                        pieces_list.append('...')
                        break

                if end:
                    pieces += right_pieces[::-1]

            s = ', '.join(pieces)
        return left + s + right

    def truncate(self, string, middle='...'):
        """
        Returns a version of `string` at most `maxparts` characters long,
        with the middle replaced by `...` if necessary.
        """
        max_parts = self.func.maxparts
        if len(string) > max_parts:
            i = max(0, (max_parts - 3) // 2)
            j = max(0, max_parts - 3 - i)
            string = string[:i] + middle + string[len(string) - j:]
        return string


@register_repr(type(ReprHelper(0, None, None).truncate))
def repr_bound_method(meth, _helper):
    obj = meth.__self__
    return '<bound method %s.%s of %s>' % (
        type_name(obj), meth.__name__, cheap_repr(obj))


@register_repr(tuple)
def repr_tuple(x, helper):
    if len(x) == 1:
        return '(%s,)' % cheap_repr(x[0], helper.level)
    else:
        return helper.repr_iterable(x, '(', ')', end=True)


@register_repr(list)
@try_register_repr('UserList', 'UserList')
@try_register_repr('collections', 'UserList')
def repr_list(x, helper):
    return helper.repr_iterable(x, '[', ']', end=True)


@register_repr(array)
@maxparts(5)
def repr_array(x, helper):
    if not x:
        return repr(x)
    return helper.repr_iterable(x, "array('%s', [" % x.typecode, '])', end=True)


@register_repr(set)
def repr_set(x, helper):
    if not x:
        return repr(x)
    elif PY2:
        return helper.repr_iterable(x, 'set([', '])')
    else:
        return helper.repr_iterable(x, '{', '}')


@register_repr(frozenset)
def repr_frozenset(x, helper):
    if not x:
        return repr(x)
    elif PY2:
        return helper.repr_iterable(x, 'frozenset([', '])')
    else:
        return helper.repr_iterable(x, 'frozenset({', '})')


@register_repr(Set)
def repr_Set(x, helper):
    if not x:
        return '%s()' % type_name(x)
    else:
        return helper.repr_iterable(x, '%s({' % type_name(x), '})')


@register_repr(deque)
def repr_deque(x, helper):
    return helper.repr_iterable(x, 'deque([', '])')


class _DirectRepr(str):
    def __repr__(self):
        return self


register_repr(_DirectRepr)(normal_repr)


@register_repr(dict)
@maxparts(4)
def repr_dict(x, helper):
    newlevel = helper.level - 1

    return helper.repr_iterable(
        (
            _DirectRepr('%s: %s' % (
                cheap_repr(key, newlevel),
                cheap_repr(x[key], newlevel),
            ))
            for key in x
        ),
        '{', '}', length=len(x),
    )


@try_register_repr('__builtin__', 'unicode')
@register_repr(str)
@maxparts(60)
def repr_str(x, helper):
    return repr(helper.truncate(x))


if PY3:
    @register_repr(bytes)
    @maxparts(60)
    def repr_bytes(x, helper):
        return repr(helper.truncate(x, middle=b'...'))


@register_repr(int)
@try_register_repr('__builtin__', 'long')
@maxparts(40)
def repr_int(x, helper):
    return helper.truncate(repr(x))


@try_register_repr('numpy', 'ndarray')
def repr_ndarray(x, _helper):
    # noinspection PyPackageRequirements
    import numpy as np

    dims = len(x.shape)
    if (
            # Too many dimensions to be concise
            dims > 6 or
            # There's a bug with array_repr and matrices
            isinstance(x, np.matrix) and np.lib.NumpyVersion(np.__version__) < '1.14.0' or
            # and with masked arrays...
            isinstance(x, np.ma.MaskedArray)

    ):
        name = type_name(x)
        if name == 'ndarray':
            name = 'array'
        return '%s(%r, shape=%r)' % (name, x.dtype, x.shape)

    edgeitems = repr_ndarray.maxparts // 2
    if dims == 3:
        edgeitems = min(edgeitems, 2)
    elif dims > 3:
        edgeitems = 1

    opts = np.get_printoptions()
    try:
        np.set_printoptions(threshold=repr_ndarray.maxparts, edgeitems=edgeitems)
        return np.array_repr(x)
    finally:
        np.set_printoptions(**opts)


@try_register_repr('pandas', 'DataFrame')
def repr_DataFrame(df, _):
    """
    This function can be configured by setting `max_rows` or `max_cols` attributes.
    """
    from pandas import get_option

    return df.to_string(
        max_rows=repr_DataFrame.max_rows,
        max_cols=repr_DataFrame.max_cols,
        show_dimensions=get_option("display.show_dimensions"),
    )


repr_DataFrame.max_rows = 8
repr_DataFrame.max_cols = 8


@try_register_repr('pandas', 'Series')
def repr_pandas_Series(series, _):
    """
    This function can be configured by setting the `max_rows` attributes.
    """
    from pandas import get_option

    return series.to_string(
        max_rows=repr_pandas_Series.max_rows,
        name=series.name,
        dtype=series.dtype,
        length=get_option("display.show_dimensions"),
    )


repr_pandas_Series.max_rows = 8


def _repr_pandas_index_generic(index, helper, attrs, long_space=False):
    klass = index.__class__.__name__
    if long_space:
        space = '\n%s' % (' ' * (len(klass) + 1))
    else:
        space = ' '

    prepr = (",%s" % space).join(
        "%s=%s" % (k, cheap_repr(v, helper.level - 1))
        for k, v in attrs)
    return "%s(%s)" % (klass, prepr)


@try_register_repr('pandas', 'Index')
def repr_pandas_Index(index, helper):
    attrs = [['dtype', index.dtype]]
    if index.name is not None:
        attrs.append(['name', index.name])
    attrs.append(['length', len(index)])
    return _repr_pandas_index_generic(index, helper, attrs)


@try_register_repr('pandas', 'IntervalIndex')
def repr_pandas_IntervalIndex(index, helper):
    attrs = [['closed', index.closed]]
    if index.name is not None:
        attrs.append(['name', index.name])
    attrs.append(['dtype', index.dtype])
    return _repr_pandas_index_generic(index, helper, attrs, long_space=True)


@try_register_repr('pandas', 'RangeIndex')
def repr_pandas_RangeIndex(index, helper):
    attrs = index._format_attrs()
    return _repr_pandas_index_generic(index, helper, attrs)


@try_register_repr('pandas', 'MultiIndex')
def repr_pandas_MultiIndex(index, helper):
    attrs = [('levels', index._levels)]

    try:
        attrs.append(('labels', index._labels))
    except AttributeError:
        attrs.append(('codes', index.codes))

    attrs.append(('names', index.names))

    if index.sortorder is not None:
        attrs.append(('sortorder', index.sortorder))
    return _repr_pandas_index_generic(index, helper, attrs, long_space=True)


@try_register_repr('pandas', 'CategoricalIndex')
def repr_pandas_CategoricalIndex(index, helper):
    attrs = [('categories', index.categories),
             ('ordered', index.ordered)]
    if index.name is not None:
        attrs.append(['name', index.name])
    attrs.append(['dtype', index.dtype.name])
    attrs.append(['length', len(index)])
    return _repr_pandas_index_generic(index, helper, attrs)


@try_register_repr('django.db.models', 'QuerySet')
def repr_QuerySet(x, _):
    try:
        model_name = x.model._meta.object_name
    except AttributeError:
        model_name = type_name(x.model)
    return '<%s instance of %s at %#x>' % (type_name(x), model_name, id(x))


@try_register_repr('collections', 'ChainMap')
@try_register_repr('chainmap', 'ChainMap')
@maxparts(4)
def repr_ChainMap(x, helper):
    return helper.repr_iterable(x.maps, type_name(x) + '(', ')', end=True)


@try_register_repr('collections', 'OrderedDict')
@try_register_repr('ordereddict', 'OrderedDict')
@try_register_repr('backport_collections', 'OrderedDict')
@maxparts(4)
def repr_OrderedDict(x, helper):
    if not x:
        return repr(x)
    helper.level += 1
    return helper.repr_iterable(viewitems(x), type_name(x) + '([', '])', length=len(x))


@try_register_repr('collections', 'UserDict')
@try_register_repr('UserDict', 'UserDict')
@register_repr(Mapping)
@maxparts(5)
def repr_Mapping(x, helper):
    if not x:
        return type_name(x) + '()'
    return '{0}({1})'.format(type_name(x), repr_dict(x, helper))


@try_register_repr('collections', 'Counter')
@try_register_repr('counter', 'Counter')
@try_register_repr('backport_collections', 'Counter')
@maxparts(5)
def repr_Counter(x, helper):
    length = len(x)
    if length <= repr_Counter.maxparts:
        return repr_Mapping(x, helper)
    else:
        # The default repr of Counter gives the items in decreasing order
        # of frequency. We don't do that because it would be expensive
        # to compute. We also don't show a sample of random keys
        # because someone familiar with the default repr might be misled
        # into thinking that they are the most common.
        return '{0}({1} keys)'.format(type_name(x), length)


@register_repr(defaultdict)
@maxparts(4)
def repr_defaultdict(x, helper):
    return '{0}({1}, {2})'.format(type_name(x),
                                  x.default_factory,
                                  repr_dict(x, helper))


def repr_Printer(x, _helper):
    contents = repr(x)
    return '{0}({1})'.format(type_name(x),
                             cheap_repr(contents))


try:
    register_repr(type(copyright))
except NameError:
    pass


if PY3:
    @register_repr(type({}.keys()))
    def repr_dict_keys(x, helper):
        return helper.repr_iterable(x, 'dict_keys([', '])')


    @register_repr(type({}.values()))
    def repr_dict_values(x, helper):
        return helper.repr_iterable(x, 'dict_values([', '])')


    @register_repr(type({}.items()))
    @maxparts(4)
    def repr_dict_items(x, helper):
        helper.level += 1
        return helper.repr_iterable(x, 'dict_items([', '])')
