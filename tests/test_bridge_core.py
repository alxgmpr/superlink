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
    def feed(self, frame, channel, now, rssi=None, snr=None):
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


# --- factory reset / unpair teardown ---

class StatusSession(FakeSession):
    """FakeSession whose feed() emits whatever events are put in `to_emit`."""
    def __init__(self, record):
        super().__init__(record)
        self.to_emit = []
    def feed(self, frame, channel, now, rssi=None, snr=None):
        evs, self.to_emit = self.to_emit, []
        return [], evs
    def tick(self, now):
        evs, self.to_emit = self.to_emit, []
        return [], evs


def _adopted_core():
    """Core with MAC already adopted and a StatusSession attached."""
    store = InMemoryDeviceStore()
    store.save(DeviceRecord(mac=MAC, adopted=True))
    core = BridgeCore(store, ProfileRegistry.load(),
                      session_factory=StatusSession)
    return core, store, core._sessions[MAC]


def test_factory_reset_confirmed_removes_device():
    """The real controller waits for the tag-matched status before issuing
    removeDevice (captures/live/bridge_adopt_fresh_pass2_DECODED.txt)."""
    from superlink.bridge.events import FactoryReset, CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag, status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC not in core._sessions
    assert store.load_all() == []
    removed = [e for e in seen if isinstance(e, DeviceRemoved)]
    assert len(removed) == 1
    assert removed[0].mac == MAC and removed[0].reason == "factory_reset"


def test_factory_reset_wrong_tag_does_not_remove():
    """A status closing some other command must not unpair the device."""
    from superlink.bridge.events import FactoryReset, CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag ^ 0xFF,
                                  status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC in core._sessions
    assert len(store.load_all()) == 1
    assert not any(isinstance(e, DeviceRemoved) for e in seen)


def test_factory_reset_nonzero_status_does_not_remove():
    """A failed reset leaves the record alone: a stale record is recoverable,
    a wrongly-deleted one needs a physical re-pair."""
    from superlink.bridge.events import FactoryReset, CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag, status_code=3)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC in core._sessions
    assert len(store.load_all()) == 1
    assert not any(isinstance(e, DeviceRemoved) for e in seen)


def test_status_without_pending_reset_does_not_remove():
    """Statuses close every command (locate, reboot, property_set). Only one
    with a pending FACTORY_RESET may tear the device down."""
    from superlink.bridge.events import CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=1, status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC in core._sessions
    assert not any(isinstance(e, DeviceRemoved) for e in seen)


def test_factory_reset_confirmed_during_tick_does_not_raise():
    """tick() iterates the session dict; teardown mutates it mid-loop unless
    the loop walks a snapshot."""
    from superlink.bridge.events import FactoryReset, CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag, status_code=0)]
    core.tick(now=5.0)
    assert MAC not in core._sessions
    assert any(isinstance(e, DeviceRemoved) for e in seen)


def test_removed_device_is_rediscoverable():
    """After a reset the sensor beacons again as unadopted; with the record
    gone the bridge must announce it as a fresh discovery, not route it to a
    dead session."""
    from superlink.bridge.events import FactoryReset, CommandStatus
    core, store, sess = _adopted_core()
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag, status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    seen = []
    core.subscribe(seen.append)
    core.feed(UNKNOWN_FRAME, channel=1, now=6.0)
    assert any(isinstance(e, DeviceDiscovered) for e in seen)


def test_stale_pending_reset_not_confirmed_by_unrelated_later_command():
    """messageTag is a single counter shared across all devices and wraps at
    255. If a FactoryReset's status is lost (no timeout exists to clear the
    pending entry — none should, per the confirm-only design), a later
    unrelated command for the same mac must not be mistaken for the reset's
    confirmation just because the shared counter reused its tag. submit()
    clears any pending reset for a mac on every submit for that mac, so only
    the most recently submitted command's tag is ever "live"."""
    from superlink.bridge.events import (
        FactoryReset, Locate, CommandStatus, DeviceRemoved,
    )
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    # The FactoryReset's status never arrives. Force the shared tag counter
    # to land on the same value for the next command, rather than looping
    # submissions 255 times to reach a real wraparound.
    core._cmd_tag = tag - 1
    core.submit(Locate(mac=MAC))
    reused_tag = sess.queued[1][1]
    assert reused_tag == tag  # confirms the forced collision actually happened
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=reused_tag, status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC in core._sessions
    assert len(store.load_all()) == 1
    assert not any(isinstance(e, DeviceRemoved) for e in seen)


def test_pending_reset_survives_unrelated_command_with_a_different_tag():
    """The invalidation guarded against aliasing is narrowed to an exact tag
    collision (finding 3). A pending FACTORY_RESET's status reply can take a
    full sensor window (seconds to minutes); an unrelated command submitted
    for the same mac in that window (a second button press, a Locate/Refresh)
    must not disarm it as long as its tag doesn't collide with the pending
    one. The reset must still be confirmed when its status finally arrives."""
    from superlink.bridge.events import (
        FactoryReset, Locate, CommandStatus, DeviceRemoved,
    )
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    core.submit(Locate(mac=MAC))          # unrelated command, distinct tag
    locate_tag = sess.queued[1][1]
    assert locate_tag != tag              # no collision this time
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag, status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC not in core._sessions
    assert store.load_all() == []
    removed = [e for e in seen if isinstance(e, DeviceRemoved)]
    assert len(removed) == 1
    assert removed[0].mac == MAC and removed[0].reason == "factory_reset"
