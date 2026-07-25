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
        self.started = False
    def start(self, now):
        self.started = True
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


def test_command_actions_use_nonzero_incrementing_tag():
    """The sensor rejects tag-0 command bodies — a tag-0 FACTORY_RESET is
    silently ignored (no 0x74 ACK, no reset; verified on hardware 2026-07-25).
    BridgeCore must stamp each command with a non-zero, incrementing messageTag."""
    from superlink.bridge.events import FactoryReset, Reboot
    store = InMemoryDeviceStore()
    store.save(DeviceRecord(mac=MAC, adopted=True))
    core = BridgeCore(store, ProfileRegistry.load(), session_factory=FakeSession)
    sess = core._sessions[MAC]
    core.submit(FactoryReset(mac=MAC))
    core.submit(Reboot(mac=MAC))
    assert [b[0] for b in sess.queued] == [7, 6]        # FACTORY_RESET, REBOOT
    assert all(b[1] != 0 for b in sess.queued)          # never tag 0
    assert sess.queued[0][1] != sess.queued[1][1]       # incrementing


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
    # messageTag is now a non-zero running counter (tag 1 for the first command),
    # not 0 — the sensor rejects tag-0 command bodies.
    assert session.queued and session.queued[0] == bytes([14, 1, 14, 0, 0x01])
