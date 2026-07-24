# tests/test_bridge_events.py
from superlink.bridge.events import (
    Event, Action, DeviceDiscovered, PropertyEvent, DeviceStateEvent,
    SetProperty, AdoptDevice, Ping, DEVICE_STATES,
)

MAC = bytes.fromhex("9041B22E9A53")


def test_property_event_fields_and_immutability():
    ev = PropertyEvent(mac=MAC, property_id=7, name="TEMPERATURE", channel=0,
                       raw=b"\x00\xd7", value=21.5, unit="°C", decoded=True)
    assert isinstance(ev, Event)
    assert ev.property_id == 7 and ev.value == 21.5 and ev.decoded is True
    import dataclasses, pytest
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.value = 0


def test_actions_are_actions_and_defaults():
    assert isinstance(SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=True), Action)
    assert Ping(mac=MAC).data == b""
    assert AdoptDevice(mac=MAC).mac == MAC


def test_device_state_values():
    assert DeviceStateEvent(mac=MAC, state="adopted").state in DEVICE_STATES
