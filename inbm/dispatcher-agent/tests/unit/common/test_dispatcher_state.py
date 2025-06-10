import io
import pickle
import pytest

from dispatcher.common.dispatcher_state import RestrictedUnpickler, restricted_load

class Dummy:
    pass

def test_restricted_unpickler_allows_builtin_types():
    # Prepare a pickle of a dict (allowed)
    data = {'foo': 'bar', 'num': 42, 'lst': [1, 2, 3]}
    buf = io.BytesIO()
    pickle.dump(data, buf)
    buf.seek(0)

    result = RestrictedUnpickler(buf).load()
    assert result == data

def test_restricted_unpickler_blocks_custom_class():
    # Prepare a pickle of a custom class (should be blocked)
    obj = Dummy()
    buf = io.BytesIO()
    pickle.dump(obj, buf)
    buf.seek(0)

    with pytest.raises(pickle.UnpicklingError):
        RestrictedUnpickler(buf).load()

def foo():
    pass

def test_restricted_unpickler_blocks_non_builtin_type():
    # Prepare a pickle of a function (should be blocked)
    buf = io.BytesIO()
    pickle.dump(foo, buf)
    buf.seek(0)

    with pytest.raises(pickle.UnpicklingError):
        RestrictedUnpickler(buf).load()

def test_restricted_load_returns_expected():
    data = {'foo': 'bar'}
    buf = io.BytesIO()
    pickle.dump(data, buf)
    buf.seek(0)
    assert restricted_load(buf) == data
