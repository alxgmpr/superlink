# tests/test_bridge_appmsg_encoders.py
from superlink import appmsg


def test_encode_property_set():
    body = appmsg.encode_property_set([(14, 0, b"\x01")], tag=0x2a)
    assert body == bytes([14, 0x2a, 14, 0, 0x01])


def test_encode_property_set_multi():
    body = appmsg.encode_property_set([(13, 0, b"\x00\x3c"), (14, 0, b"\x00")])
    assert body == bytes([14, 0, 13, 0, 0x00, 0x3c, 14, 0, 0x00])


def test_encode_simple_commands():
    assert appmsg.encode_reboot(1) == bytes([6, 1])
    assert appmsg.encode_factory_reset(2) == bytes([7, 2])
    assert appmsg.encode_locate(3) == bytes([8, 3])


def test_factory_reset_default_tag_is_nonzero():
    # The sensor silently ignores a tag-0 FACTORY_RESET (0700). The default
    # must be non-zero; 0x35 is the ground-truth controller value we verified
    # end-to-end on hardware (bridge_adopt_fresh_pass2_DECODED.txt -> 0735).
    body = appmsg.encode_factory_reset()
    assert body == bytes([7, 0x35])
    assert body[1] != 0
