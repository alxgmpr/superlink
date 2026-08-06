from superlink.bridge.config import RuntimeConfig, MqttConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime, start_mqtt_if_configured
from superlink.bridge.store import InMemoryDeviceStore, DeviceRecord
from superlink.bridge.mqtt import MqttBridge
from tests.support.fake_hal import FakeHal
from tests.support.fake_mqtt import FakeMqttClient

MAC = bytes.fromhex("9041B22E9A53")
MH = MAC.hex()
# 0x54 UL data frame from MAC (header + >=4 encrypted bytes); content is
# irrelevant here since the session's feed() is monkeypatched below -- this
# just needs to parse and route to the already-registered session.
UNKNOWN_FRAME = bytes.fromhex("E054" + MH + "5B11" + "9CFFC24C" + "8A")


def _rt(mqtt):
    cfg = RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                        pairing_key=DEFAULT_PAIRING_KEY, adopt=ADOPT_ALL, mqtt=mqtt)
    return cfg, BridgeRuntime(cfg, FakeHal(), store=InMemoryDeviceStore())


def test_no_mqtt_returns_none():
    cfg, rt = _rt(None)
    assert start_mqtt_if_configured(rt, cfg, client=FakeMqttClient()) is None


def test_mqtt_configured_starts_bridge():
    cfg, rt = _rt(MqttConfig(host="h"))
    client = FakeMqttClient()
    bridge = start_mqtt_if_configured(rt, cfg, client=client)
    assert isinstance(bridge, MqttBridge)
    assert client.connected and client.loop_running    # start() ran


# --- cross-layer: FactoryReset confirmation through core -> runtime -> MQTT ---

def _retracted(client, topic):
    """True if the LAST publish to `topic` was an empty retained payload."""
    for t, p, retain in reversed(client.published):
        if t == topic:
            return p == "" and retain
    return False


def test_factory_reset_prunes_runtime_sessions_and_retracts_signal():
    """Regression for findings 1 and 2 of the factory-reset/unpair review.

    (1) BridgeRuntime._sessions is runtime-owned and only ever grew; a
    confirmed removal dropped BridgeCore's copy but left the runtime's copy
    behind, so a later shutdown flush (`run()`'s finally block) would
    resurrect the deleted DeviceRecord.

    (2) The confirming status arrives on the same frame as a LinkSignal
    (session._handle_active appends one whenever rssi is present, which
    runtime.poll_once always supplies). If retraction (triggered by the
    CommandStatus, via _intercept) ran before the rest of the batch reached
    MqttBridge (via _emit), the LinkSignal would republish SIGNAL discovery
    and state for a device that no longer exists -- a ghost entity nothing
    would ever retract.

    Adopts a device, submits a FactoryReset, then feeds a single batch
    containing both the confirming CommandStatus and a LinkSignal (the real
    on-wire shape) through BridgeCore.feed(). Must fail if fix 1 or fix 2 is
    reverted.
    """
    from superlink.bridge.events import FactoryReset, CommandStatus, LinkSignal

    cfg = RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                        pairing_key=DEFAULT_PAIRING_KEY, adopt=ADOPT_ALL,
                        mqtt=MqttConfig(host="h"))
    store = InMemoryDeviceStore()
    store.save(DeviceRecord(mac=MAC, adopted=True))
    rt = BridgeRuntime(cfg, FakeHal(), store=store)
    client = FakeMqttClient()
    bridge = MqttBridge(cfg.mqtt, rt, client)
    bridge.start()

    # BridgeCore.__init__ built the session via runtime._session_factory, so
    # it is registered in both core._sessions and runtime._sessions -- the
    # exact aliasing finding 1 relies on.
    assert MAC in rt._sessions
    session = rt._sessions[MAC]

    # Capture the messageTag FactoryReset queues, the way the real sensor
    # would echo it in its CommandStatus.
    tags = []
    orig_queue_body = session.queue_body
    def _capture(body):
        tags.append(body[1])
        orig_queue_body(body)
    session.queue_body = _capture
    rt.core.submit(FactoryReset(mac=MAC))
    tag = tags[0]

    # Real captured batch: CommandStatus + LinkSignal on the same UL data
    # frame. Bypass the real DeviceSession's decrypt/decode path and hand
    # BridgeCore exactly this batch, as the StatusSession fakes in
    # test_bridge_core.py do.
    batch = [CommandStatus(mac=MAC, message_tag=tag, status_code=0),
             LinkSignal(mac=MAC, rssi_dbm=-40.0, snr=8.0)]
    session.feed = lambda frame, channel, now, rssi=None, snr=None: ([], batch)

    rt.core.feed(UNKNOWN_FRAME, channel=1, now=5.0, rssi=-40.0, snr=8.0)

    # (a) the store no longer has the device
    assert store.load_all() == []
    # (b) the runtime's session dict no longer holds the mac (finding 1)
    assert MAC not in rt._sessions
    # (c) no non-empty retained topic remains for the mac -- specifically
    # including the SIGNAL discovery config and state the LinkSignal in the
    # same batch would otherwise republish after retraction (finding 2).
    assert bridge._retained.get(MAC, set()) == set()
    assert _retracted(client, f"homeassistant/sensor/{MH}_SIGNAL/config")
    assert _retracted(client, f"superlink/{MH}/SIGNAL")
