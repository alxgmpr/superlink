from superlink.bridge.config import RuntimeConfig, MqttConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime, start_mqtt_if_configured
from superlink.bridge.store import InMemoryDeviceStore
from superlink.bridge.mqtt import MqttBridge
from tests.support.fake_hal import FakeHal
from tests.support.fake_mqtt import FakeMqttClient


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
