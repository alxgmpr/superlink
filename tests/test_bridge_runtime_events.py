from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore, DeviceRecord
from superlink.bridge.events import (
    DeviceDiscovered, DeviceStateEvent, PropertyEvent, AdoptDevice,
    DeviceInfoEvent,
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


def test_adopted_state_auto_pushes_post_adoption_config():
    # On commit, the bridge must replay the controller's post-adoption config
    # (REPORT_INTERVAL=300, TAMPER_CONFIG=1, ENTRY_CONFIG=1) so door/tamper
    # reporting persists across restarts/re-pairs with no manual step.
    from superlink.bridge.events import SetPropertyRaw
    store = InMemoryDeviceStore()
    rt = _runtime({MAC}, store=store)
    rt._sessions[MAC] = _FakeSession(MAC)
    submitted = []
    rt.core.submit = lambda a: submitted.append(a)
    rt._on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    raws = [(a.property_id, a.channel, a.raw) for a in submitted
            if isinstance(a, SetPropertyRaw)]
    assert raws == [
        (13, 0, b"\x01\x2c"),
        (21, 0, b"\x00\x01"),
        (16, 0, b"\x00\x01"),
    ]


def test_device_info_event_persists_prop_sizes():
    # prop_sizes is learned only from a DEVICE_INFO_REPORT, which arrives well
    # after the initial adopt-time save. The runtime must re-persist the record
    # then, so a restart keeps the sizes and PROPERTY_REPORTs still decode.
    store = InMemoryDeviceStore()
    rt = _runtime({MAC}, store=store)

    class _SessionWithSizes:
        def to_record(self):
            return DeviceRecord(mac=MAC, adopted=True, prop_sizes={1: 4, 3: 4})

    rt._sessions[MAC] = _SessionWithSizes()
    rt._on_event(DeviceInfoEvent(
        mac=MAC, device_type=0xAE94, fw_version=(1, 2, 0), hw_revision=4,
        anon_id=b"\x00" * 16, supported_message_ids=[], supported_properties=[]))
    saved = store.load_all()
    assert len(saved) == 1 and saved[0].prop_sizes == {1: 4, 3: 4}


def test_discovered_state_event_deletes_stale_record():
    # A factory-reset device re-advertises as unadopted; the session emits
    # DeviceStateEvent(state="discovered"). The runtime must drop the stale
    # adopted record so the fresh pair re-adopts cleanly.
    store = InMemoryDeviceStore()
    store.save(DeviceRecord(mac=MAC, adopted=True))
    rt = _runtime({MAC}, store=store)
    rt._on_event(DeviceStateEvent(mac=MAC, state="discovered"))
    assert all(r.mac != MAC for r in store.load_all())


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
