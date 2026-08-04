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


def test_button_press_emits_edge_event_on_increase(reg):
    from superlink.bridge.events import ButtonPressed
    sizes = {19: 4}
    last: dict = {}

    def report(uptime):
        body = bytes([12, 0]) + bytes([19, 0]) + uptime.to_bytes(4, "big")
        return events_from_app_message(MAC, body, reg, sizes=sizes,
                                       last_values=last)

    # First sighting establishes the baseline — a PropertyEvent, but NO press
    # (the sensor reports the last-press uptime continuously; only a *new* press
    # advances it, so the first value we ever see is not itself an edge).
    evs = report(1000)
    assert [type(e) for e in evs] == [PropertyEvent]
    assert evs[0].name == "BUTTON_PRESSED" and evs[0].value == 1000

    # Same value again: still no press.
    assert [type(e) for e in report(1000)] == [PropertyEvent]

    # Uptime advances: a press happened -> ButtonPressed alongside the report.
    evs = report(1500)
    assert [type(e) for e in evs] == [PropertyEvent, ButtonPressed]
    assert evs[1].mac == MAC and evs[1].property_id == 19
    assert evs[1].name == "BUTTON_PRESSED"


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


def test_action_to_body_header_only_commands(reg):
    from superlink.bridge.events import Locate, RequestDeviceInfo, FactoryReset
    assert action_to_body(Locate(mac=MAC), reg, tag=4) == bytes([8, 4])
    assert action_to_body(RequestDeviceInfo(mac=MAC), reg, tag=5) == bytes([9, 5])
    assert action_to_body(FactoryReset(mac=MAC), reg, tag=6) == bytes([7, 6])


def test_action_to_body_set_property_raw(reg):
    from superlink.bridge.events import SetPropertyRaw
    body = action_to_body(
        SetPropertyRaw(mac=MAC, property_id=13, channel=0, raw=b"\x00\x3c"),
        reg, tag=7)
    assert body == bytes([14, 7, 13, 0, 0x00, 0x3c])


def test_adopt_has_no_body(reg):
    from superlink.bridge.events import AdoptDevice
    with pytest.raises(TypeError):
        action_to_body(AdoptDevice(mac=MAC), reg)


def test_battery_report_also_emits_voltage(reg):
    """Real 4-byte BATTERY payload yields both the percent and the millivolts."""
    raw = bytes.fromhex("5a0ba000")             # 90 %, 2976 mV
    body = bytes([12, 0]) + bytes([3, 0]) + raw
    evs = events_from_app_message(MAC, body, reg, sizes={3: 4})
    assert [(e.name, e.value, e.unit) for e in evs] == [
        ("BATTERY", 90, "%"),
        ("BATTERY_VOLTAGE", pytest.approx(2.976), "V"),
    ]
    assert all(e.property_id == 3 and e.decoded for e in evs)
