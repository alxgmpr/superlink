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
