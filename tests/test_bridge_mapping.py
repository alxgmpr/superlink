import pytest
from superlink import appmsg
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.mapping import events_from_app_message, action_to_body
from superlink.bridge.events import (
    PropertyEvent, DeviceInfoEvent, RawMessageEvent,
    SetProperty, RequestProperty, Reboot, Ping,
)

MAC = bytes.fromhex("9041B22E9A53")


@pytest.fixture
def reg():
    return ProfileRegistry.load()


def test_property_report_maps_to_events(reg):
    # PROPERTY_REPORT (id 12): LEAK_DETECTED(4) ch0 = 01, BATTERY(3) ch0 = 50
    body = bytes([12, 0]) + bytes([4, 0, 0x01]) + bytes([3, 0, 50])
    sizes = {4: 1, 3: 1}
    evs = events_from_app_message(MAC, body, reg, sizes=sizes)
    assert [type(e) for e in evs] == [PropertyEvent, PropertyEvent]
    assert evs[0].name == "LEAK_DETECTED" and evs[0].value is True
    assert evs[1].name == "BATTERY" and evs[1].value == 50 and evs[1].unit == "%"


def test_unknown_message_is_raw(reg):
    body = bytes([200, 7, 0xaa, 0xbb])
    evs = events_from_app_message(MAC, body, reg)
    assert len(evs) == 1 and isinstance(evs[0], RawMessageEvent)
    assert evs[0].message_id == 200 and evs[0].body == b"\xaa\xbb"


def test_action_to_body_set_property(reg):
    body = action_to_body(SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=True), reg, tag=9)
    assert body == bytes([14, 9, 14, 0, 0x01])


def test_action_to_body_requests_and_commands(reg):
    assert action_to_body(RequestProperty(mac=MAC, ids=[3, 7]), reg, tag=1) == bytes([11, 1, 3, 7])
    assert action_to_body(Reboot(mac=MAC), reg, tag=2) == bytes([6, 2])
    assert action_to_body(Ping(mac=MAC, data=b"\xff"), reg, tag=3) == bytes([4, 3, 0xff])


def test_adopt_has_no_body(reg):
    from superlink.bridge.events import AdoptDevice
    with pytest.raises(TypeError):
        action_to_body(AdoptDevice(mac=MAC), reg)
