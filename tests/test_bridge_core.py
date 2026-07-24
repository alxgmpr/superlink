from superlink.bridge.core import BridgeCore, OutgoingFrame
from superlink.bridge.store import InMemoryDeviceStore, DeviceRecord
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.events import (
    DeviceDiscovered, DeviceStateEvent, PropertyEvent, AdoptDevice, Event,
)

MAC = bytes.fromhex("9041B22E9A53")
# 0x54 UL data frame from an unknown MAC (header + >=4 encrypted bytes)
UNKNOWN_FRAME = bytes.fromhex("E054" + MAC.hex() + "5B11" + "9CFFC24C" + "8A")


class FakeSession:
    """Test double implementing SessionProtocol; emits one PropertyEvent per feed."""
    def __init__(self, record):
        self.mac = record.mac
        self.state = "adopted"
        self.queued = []
    def feed(self, frame, channel, now):
        ev = PropertyEvent(mac=self.mac, property_id=3, name="BATTERY",
                           channel=0, raw=b"\x64", value=100, unit="%", decoded=True)
        return [], [ev]
    def tick(self, now):
        return [], []
    def queue_body(self, body):
        self.queued.append(body)


def _core(auto_adopt=False):
    return BridgeCore(InMemoryDeviceStore(), ProfileRegistry.load(),
                      session_factory=FakeSession, auto_adopt=auto_adopt)


def test_unknown_device_is_discovered_not_adopted():
    core = _core()
    seen = []
    core.subscribe(seen.append)
    core.feed(UNKNOWN_FRAME, channel=1, now=1.0)
    kinds = [type(e) for e in seen]
    assert DeviceDiscovered in kinds
    assert not any(isinstance(e, PropertyEvent) for e in seen)
    # A second frame from the same undiscovered->discovered MAC does not re-announce
    seen.clear()
    core.feed(UNKNOWN_FRAME, channel=1, now=2.0)
    assert not any(isinstance(e, DeviceDiscovered) for e in seen)


def test_adopt_action_promotes_and_then_events_flow():
    core = _core()
    seen = []
    core.subscribe(seen.append)
    core.feed(UNKNOWN_FRAME, channel=1, now=1.0)      # discovered
    core.submit(AdoptDevice(mac=MAC))                  # approve
    seen.clear()
    core.feed(UNKNOWN_FRAME, channel=1, now=3.0)      # now routed to session
    assert any(isinstance(e, PropertyEvent) and e.value == 100 for e in seen)


def test_auto_adopt_skips_approval():
    core = _core(auto_adopt=True)
    seen = []
    core.subscribe(seen.append)
    core.feed(UNKNOWN_FRAME, channel=1, now=1.0)
    # session created immediately; its event surfaces without an explicit adopt
    assert any(isinstance(e, PropertyEvent) for e in seen)


def test_submit_setproperty_queues_body_on_session():
    from superlink.bridge.events import SetProperty
    core = _core(auto_adopt=True)
    core.feed(UNKNOWN_FRAME, channel=1, now=1.0)
    core.submit(SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=True))
    session = core._sessions[MAC]
    assert session.queued and session.queued[0] == bytes([14, 0, 14, 0, 0x01])
