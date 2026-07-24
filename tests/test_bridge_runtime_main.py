from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import build_runtime, BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore
from tests.support.fake_hal import FakeHal


def test_build_runtime_wires_core_and_hal():
    cfg = RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                        pairing_key=DEFAULT_PAIRING_KEY, adopt=ADOPT_ALL)
    hal = FakeHal()
    rt = build_runtime(cfg, hal, store=InMemoryDeviceStore())
    assert isinstance(rt, BridgeRuntime)
    assert rt.hal is hal and rt.core is not None
