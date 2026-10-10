import pytest

from netscan.core.registry import available_engines, get_engine, register_engine


def test_unknown_engine_raises_helpful_error():
    with pytest.raises(ValueError, match="available"):
        get_engine("does-not-exist")


def test_custom_engine_registers():
    @register_engine("test-engine")
    def dummy(host, ports, **kwargs):
        return [22]

    assert "test-engine" in available_engines()
    assert get_engine("test-engine")("h", []) == [22]


def test_builtin_engines_registered_on_import():
    import netscan.portscan  # noqa: F401  (import side-effect registers engines)

    assert {"async", "connect", "syn"} <= set(available_engines())
