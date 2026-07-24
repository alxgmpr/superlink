from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore, DeviceRecord
from superlink.bridge.events import (
    DeviceDiscovered, DeviceStateEvent, PropertyEvent, AdoptDevice,
)
from tests.support.fake_hal import FakeHal

MAC = bytes.fromhex("9041B22E9A53")
OTHER = bytes.fromhex("001122334455")


def _cfg(adopt):
    return RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                         pairing_key=DEFAULT_PAIRING_KEY, adopt=adopt)


def _runtime(adopt, store=None):
    return BridgeRuntime(_cfg(adopt), FakeHal(), store=store or InMemoryDeviceStore())


def test_discovered_allowed_mac_is_adopted():
    rt = _runtime({MAC})
    submitted = []
    rt.core.submit = lambda a: submitted.append(a)   # capture submits
    rt._on_event(DeviceDiscovered(mac=MAC, channel=1, first_seen=1.0))
    assert any(isinstance(a, AdoptDevice) and a.mac == MAC for a in submitted)


def test_discovered_disallowed_mac_is_not_adopted():
    rt = _runtime({MAC})
    submitted = []
    rt.core.submit = lambda a: submitted.append(a)
    rt._on_event(DeviceDiscovered(mac=OTHER, channel=1, first_seen=1.0))
    assert submitted == []


def test_adopt_all():
    rt = _runtime(ADOPT_ALL)
    submitted = []
    rt.core.submit = lambda a: submitted.append(a)
    rt._on_event(DeviceDiscovered(mac=OTHER, channel=1, first_seen=1.0))
    assert len(submitted) == 1


def test_adopted_state_persists_record():
    store = InMemoryDeviceStore()
    rt = _runtime({MAC}, store=store)
    # Simulate a session the core built for this mac.
    rt._sessions[MAC] = _FakeSession(MAC)
    rt._on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    saved = store.load_all()
    assert len(saved) == 1 and saved[0].mac == MAC


def test_property_event_reaches_sink():
    rt = _runtime({MAC})
    seen = []
    rt.add_event_sink(seen.append)
    ev = PropertyEvent(mac=MAC, property_id=3, name="BATTERY", channel=0,
                       raw=b"\x64", value=100, unit="%", decoded=True)
    rt._on_event(ev)
    assert ev in seen


class _FakeSession:
    def __init__(self, mac):
        self._mac = mac
    def to_record(self):
        return DeviceRecord(mac=self._mac, adopted=True)
