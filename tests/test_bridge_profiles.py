import pytest
from superlink.bridge.profiles import ProfileRegistry


@pytest.fixture
def reg():
    return ProfileRegistry.load()


def test_decode_known_scaled(reg):
    # TEMPERATURE (id 7): s16 big-endian, scale 0.1
    value, unit, decoded = reg.decode(7, (215).to_bytes(2, "big"))
    assert decoded is True and value == pytest.approx(21.5) and unit == "°C"


def test_decode_bool(reg):
    value, unit, decoded = reg.decode(4, b"\x01")  # LEAK_DETECTED
    assert decoded is True and value is True


def test_decode_unknown_passes_through(reg):
    value, unit, decoded = reg.decode(200, b"\xde\xad")
    assert decoded is False and value is None and unit is None


def test_encode_roundtrip(reg):
    pid, raw = reg.encode("LED_ENABLED", True)  # id 14, bool, rw
    assert pid == 14 and raw == b"\x01"


def test_encode_readonly_raises(reg):
    with pytest.raises(PermissionError):
        reg.encode("BATTERY", 50)  # id 3, read-only


def test_resolve_and_name(reg):
    assert reg.resolve_id("TEMPERATURE") == 7
    assert reg.resolve_id(7) == 7
    assert reg.name(999) == "UNKNOWN_999"
    with pytest.raises(KeyError):
        reg.resolve_id("NOPE")
