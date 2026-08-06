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


def test_button_pressed_decodes_as_u32_not_bool(reg):
    # id19 is a u32 last-press-uptime timestamp, not a bool. A nonzero raw must
    # decode to the integer uptime, not a constant True (the old constant-ON bug).
    value, unit, decoded = reg.decode(19, (123456).to_bytes(4, "big"))
    assert decoded is True and value == 123456


def test_button_pressed_marked_edge_increase(reg):
    assert reg.edge(19) == "increase"
    assert reg.edge(4) is None  # LEAK_DETECTED is a plain bool, no edge


def test_post_adoption_default_config(reg):
    # The controller enables door/tamper reporting post-adoption with three
    # PROPERTY_SETs (ground truth bridge_adopt_fresh_pass2):
    #   REPORT_INTERVAL(13)=300, TAMPER_CONFIG(21)=1, ENTRY_CONFIG(16)=1.
    cfg = reg.post_adoption(None)
    assert cfg == [
        (13, 0, b"\x01\x2c"),
        (21, 0, b"\x00\x01"),
        (16, 0, b"\x00\x01"),
    ]


def test_battery_extras_decode_millivolts(reg):
    """BATTERY payload is [percent][mV:u16][reserved] — real capture bytes."""
    raw = bytes.fromhex("5a0ba000")            # 90 %, 2976 mV
    value, unit, decoded = reg.decode(3, raw)
    assert (value, unit, decoded) == (90, "%", True)   # primary unchanged
    assert reg.extras(3, raw) == [("BATTERY_VOLTAGE", pytest.approx(2.976), "V")]


def test_battery_extras_skipped_on_short_payload(reg):
    """A 1-byte BATTERY can't hold the mV field — emit nothing, not a zero."""
    assert reg.extras(3, b"\x5a") == []
    assert reg.extras(3, b"\x5a\x0b") == []     # u16 straddles the end


def test_extras_empty_for_properties_without_them(reg):
    assert reg.extras(4, b"\x01") == []         # LEAK_DETECTED
    assert reg.extras(200, b"\xde\xad") == []   # unknown id
