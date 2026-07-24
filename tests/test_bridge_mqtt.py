import json
from superlink.bridge.config import RuntimeConfig, MqttConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore
from superlink.bridge.mqtt import MqttBridge
from superlink.bridge.events import (
    PropertyEvent, DeviceDiscovered, SetProperty, AdoptDevice,
)
from tests.support.fake_hal import FakeHal
from tests.support.fake_mqtt import FakeMqttClient

MAC = bytes.fromhex("9041B22E9A53")
MH = MAC.hex()


def _bridge():
    cfg = RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                        pairing_key=DEFAULT_PAIRING_KEY, adopt=ADOPT_ALL,
                        mqtt=MqttConfig(host="h"))
    rt = BridgeRuntime(cfg, FakeHal(), store=InMemoryDeviceStore())
    client = FakeMqttClient()
    bridge = MqttBridge(cfg.mqtt, rt, client)
    return rt, client, bridge


def test_property_event_publishes_state_and_discovery():
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(PropertyEvent(mac=MAC, property_id=4, name="LEAK_DETECTED",
                                  channel=0, raw=b"\x01", value=True, unit=None,
                                  decoded=True))
    assert client.find(f"superlink/{MH}/LEAK_DETECTED") == "ON"
    cfg_topic = f"homeassistant/binary_sensor/{MH}_LEAK_DETECTED/config"
    disc = client.find(cfg_topic)
    assert disc is not None and json.loads(disc)["device_class"] == "moisture"


def test_discovery_published_once():
    rt, client, bridge = _bridge()
    bridge.start()
    ev = PropertyEvent(mac=MAC, property_id=3, name="BATTERY", channel=0,
                       raw=b"\x64", value=100, unit="%", decoded=True)
    bridge.on_event(ev); bridge.on_event(ev)
    cfg_topic = f"homeassistant/sensor/{MH}_BATTERY/config"
    n = sum(1 for t, _, _ in client.published if t == cfg_topic)
    assert n == 1


def test_discovered_device_published():
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(DeviceDiscovered(mac=MAC, channel=1, first_seen=1.0))
    assert client.find(f"superlink/discovered/{MH}") is not None


def test_inbound_set_submits_action():
    rt, client, bridge = _bridge()
    got = []
    rt.submit_action = lambda a: got.append(a)
    bridge.start()
    bridge._on_message(f"superlink/{MH}/LED_ENABLED/set", "ON")
    assert len(got) == 1 and isinstance(got[0], SetProperty)
    assert got[0].mac == MAC and got[0].name_or_id == "LED_ENABLED" and got[0].value is True


def test_inbound_adopt_submits_action():
    rt, client, bridge = _bridge()
    got = []
    rt.submit_action = lambda a: got.append(a)
    bridge.start()
    bridge._on_message("superlink/adopt", MH)
    assert len(got) == 1 and isinstance(got[0], AdoptDevice) and got[0].mac == MAC


def test_start_sets_lwt_and_online():
    rt, client, bridge = _bridge()
    bridge.start()
    assert client.lwt == ("superlink/bridge/availability", "offline", True)
    assert client.find("superlink/bridge/availability") == "online"
    assert f"superlink/+/+/set" in client.subscriptions
    assert "superlink/adopt" in client.subscriptions
