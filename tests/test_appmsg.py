"""Tests for the SuperLink application-layer message codec (appmsg).

Wire format (inside the encrypted frame body), per Protect module 41118:
    [1B messageId] [1B messageTag] [payload...]
"""
import pytest
from superlink import appmsg


# ---- encoders (gateway -> sensor) ----

def test_encode_device_info_request():
    """DEVICE_INFO_REQUEST (9) is just [msgId, tag], no payload."""
    assert appmsg.encode_device_info_request(tag=0x7c) == bytes([0x09, 0x7c])


def test_encode_property_request_ids():
    """PROPERTY_REQUEST (11) is [msgId, tag] followed by raw property-id bytes.

    Critically: NO validation — any id 0-255 is serialized verbatim. This is
    the memory-disclosure fuzzing primitive.
    """
    out = appmsg.encode_property_request([0x11, 0x01, 0x0d, 0x14], tag=0x05)
    assert out == bytes([0x0b, 0x05, 0x11, 0x01, 0x0d, 0x14])


def test_encode_property_request_accepts_undefined_ids():
    """Undefined ids (0, 18, 43-255) must pass through unfiltered."""
    out = appmsg.encode_property_request([0x00, 0x12, 0xff], tag=0)
    assert out == bytes([0x0b, 0x00, 0x00, 0x12, 0xff])


def test_encode_property_request_rejects_out_of_byte_range():
    with pytest.raises(ValueError):
        appmsg.encode_property_request([256], tag=0)


# ---- decoders (sensor -> gateway) ----

def _device_info_report() -> bytes:
    return bytes([
        0x0a, 0x00,               # msgId=DEVICE_INFO_REPORT, tag
        0x00, 0x07,               # deviceType
        0x00, 0x01,               # fw major
        0x00, 0x02,               # fw minor
        0x00, 0x03,               # fw patch
        0xa1, 0x12, 0x60, 0x63,   # fwBuildId (u32)
        0x02,                     # hardwareRevision
    ]) + bytes(range(16)) + bytes([   # anonymousDeviceId (16B)
        0x03, 0x09, 0x0b, 0x0c,   # supportedMessageIds: count=3, [9,11,12]
        0x02,                     # supportedProperties: count=2
        0x01, 0x01, 0x04,         # UPTIME  ch=1 valueSize=4
        0x03, 0x01, 0x01,         # BATTERY ch=1 valueSize=1
    ])


def test_decode_device_info_report():
    r = appmsg.decode_message(_device_info_report())
    assert r["messageId"] == 10
    assert r["deviceType"] == 0x0007
    assert r["fwVersion"] == (1, 2, 3)
    assert r["fwBuildId"] == "a1126063"
    assert r["hardwareRevision"] == 2
    assert r["anonymousDeviceId"] == bytes(range(16))
    assert r["supportedMessageIds"] == [9, 11, 12]
    assert r["supportedProperties"] == [
        {"propertyId": 1, "channelCount": 1, "valueSize": 4},
        {"propertyId": 3, "channelCount": 1, "valueSize": 1},
    ]


def test_property_sizes_from_device_info():
    """The report yields the value-size map needed to parse PROPERTY_REPORTs."""
    r = appmsg.decode_message(_device_info_report())
    assert appmsg.property_sizes(r) == {1: 4, 3: 1}


def test_decode_property_report_with_sizes():
    body = bytes([
        0x0c, 0x00,               # msgId=PROPERTY_REPORT, tag
        0x01, 0x00,               # UPTIME ch=0
        0x00, 0x00, 0x01, 0x00,   #   value (4B per size map)
        0x03, 0x00,               # BATTERY ch=0
        0x4b,                     #   value (1B)
    ])
    r = appmsg.decode_message(body, sizes={1: 4, 3: 1})
    assert r["messageId"] == 12
    assert r["properties"] == [
        {"propertyId": 1, "channel": 0, "value": bytes([0, 0, 1, 0]),
         "known": True},
        {"propertyId": 3, "channel": 0, "value": bytes([0x4b]),
         "known": True},
    ]


def test_decode_property_report_dynamic_size():
    """valueSize 0 = dynamic: a length byte precedes the value."""
    body = bytes([
        0x0c, 0x00,
        0x11, 0x00,               # id 0x11 ch=0
        0x03, 0x41, 0x42, 0x43,   # len=3, value "ABC"
    ])
    r = appmsg.decode_message(body, sizes={0x11: 0})
    assert r["properties"] == [
        {"propertyId": 0x11, "channel": 0, "value": b"ABC", "known": True},
    ]


def test_decode_property_report_unknown_id_returns_raw():
    """An undefined property id (not in the size map) is the payoff case:
    we can't know its declared size, so capture the remaining bytes raw and
    flag it as unknown rather than raising."""
    body = bytes([
        0x0c, 0x00,
        0x2a, 0x00,               # id 42 (0x2a) — not in size map
        0xde, 0xad, 0xbe, 0xef,   # whatever the sensor leaked
    ])
    r = appmsg.decode_message(body, sizes={1: 4})
    assert r["properties"] == [
        {"propertyId": 0x2a, "channel": 0, "value": bytes.fromhex("deadbeef"),
         "known": False},
    ]


def test_decode_request_status_response():
    r = appmsg.decode_message(bytes([0x01, 0x00, 0x11]))
    assert r["messageId"] == 1
    assert r["statusCode"] == 0x11


def test_property_name_known_and_unknown():
    assert appmsg.property_name(1) == "UPTIME"
    assert appmsg.property_name(17) == "FIRMWARE_VERSION"
    assert appmsg.property_name(43) == "UNKNOWN_43"    # first undefined id
