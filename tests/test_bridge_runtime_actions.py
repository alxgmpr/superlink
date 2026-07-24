import threading
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore
from superlink.bridge.events import SetProperty
from tests.support.fake_hal import FakeHal

MAC = bytes.fromhex("9041B22E9A53")


def _rt():
    cfg = RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                        pairing_key=DEFAULT_PAIRING_KEY, adopt=ADOPT_ALL)
    return BridgeRuntime(cfg, FakeHal(), store=InMemoryDeviceStore())


def test_submit_action_is_drained_to_core_on_poll():
    rt = _rt()
    got = []
    rt.core.submit = lambda a: got.append(a)
    a = SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=True)
    rt.submit_action(a)
    assert got == []                    # not applied until drained
    rt.poll_once(now=1.0)               # drains at top (no packets needed)
    assert got == [a]


def test_submit_action_thread_safe():
    rt = _rt()
    got = []
    rt.core.submit = lambda a: got.append(a)
    def worker(i):
        rt.submit_action(SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=i))
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    rt.poll_once(now=1.0)
    assert len(got) == 20
