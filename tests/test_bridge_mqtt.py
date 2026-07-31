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


# --- link signal (gateway RSSI in dBm) ---

def test_link_signal_publishes_rssi_dbm():
    from superlink.bridge.events import LinkSignal
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(LinkSignal(mac=MAC, rssi_dbm=-42.5, snr=9.0))
    assert client.find(f"superlink/{MH}/SIGNAL") == "-42"
    cfg = client.find(f"homeassistant/sensor/{MH}_SIGNAL/config")
    assert cfg is not None
    payload = json.loads(cfg)
    assert payload["device_class"] == "signal_strength"
    assert payload["unit_of_measurement"] == "dBm"


# --- physical button press (id19 edge) ---

def test_button_pressed_publishes_ha_event():
    from superlink.bridge.events import ButtonPressed
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(ButtonPressed(mac=MAC, property_id=19,
                                  name="BUTTON_PRESSED", value=1500))
    # A physical button has no discrete "off" — surface it as an HA `event`
    # entity (a press trigger with a timestamp), not an on/off binary_sensor.
    state = client.find(f"superlink/{MH}/BUTTON")
    assert json.loads(state)["event_type"] == "press"
    cfg = client.find(f"homeassistant/event/{MH}_BUTTON/config")
    assert cfg is not None
    payload = json.loads(cfg)
    assert payload["event_types"] == ["press"]
    assert payload["state_topic"] == f"superlink/{MH}/BUTTON"
    assert "payload_on" not in payload and "payload_off" not in payload


# --- command buttons: LOCATE / REBOOT / refresh ---

def test_start_subscribes_button_press_topic():
    rt, client, bridge = _bridge()
    bridge.start()
    assert "superlink/+/+/press" in client.subscriptions


def test_resubscribes_on_broker_reconnect():
    # paho drops subscriptions when the broker connection drops and does NOT
    # restore them on auto-reconnect unless (re)subscribed in on_connect. Without
    # that, HA commands silently stop being received after any broker blip.
    rt, client, bridge = _bridge()
    bridge.start()
    client.subscriptions.clear()      # broker dropped -> subs gone
    client.fire_on_connect()          # auto-reconnect fires on_connect again
    assert "superlink/+/+/set" in client.subscriptions
    assert "superlink/+/+/press" in client.subscriptions
    assert "superlink/adopt" in client.subscriptions


def test_button_press_locate_submits_action():
    from superlink.bridge.events import Locate
    rt, client, bridge = _bridge()
    got = []
    rt.submit_action = lambda a: got.append(a)
    bridge.start()
    bridge._on_message(f"superlink/{MH}/locate/press", "PRESS")
    assert len(got) == 1 and isinstance(got[0], Locate) and got[0].mac == MAC


def test_button_press_reboot_submits_action():
    from superlink.bridge.events import Reboot
    rt, client, bridge = _bridge()
    got = []
    rt.submit_action = lambda a: got.append(a)
    bridge.start()
    bridge._on_message(f"superlink/{MH}/reboot/press", "PRESS")
    assert len(got) == 1 and isinstance(got[0], Reboot) and got[0].mac == MAC


def test_clear_tamper_button_submits_property_set_raw():
    from superlink.bridge.events import SetPropertyRaw
    rt, client, bridge = _bridge()
    got = []
    rt.submit_action = lambda a: got.append(a)
    bridge.start()
    bridge._on_message(f"superlink/{MH}/clear_tamper/press", "PRESS")
    assert len(got) == 1 and isinstance(got[0], SetPropertyRaw)
    assert got[0].mac == MAC and got[0].property_id == 22
    assert got[0].channel == 0 and got[0].raw == b"\x01"


def test_clear_tamper_button_discovery_published():
    from superlink.bridge.events import DeviceStateEvent
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    cfg = client.find(f"homeassistant/button/{MH}_clear_tamper/config")
    assert cfg is not None
    assert json.loads(cfg)["command_topic"] == f"superlink/{MH}/clear_tamper/press"


def test_refresh_button_requests_device_info():
    from superlink.bridge.events import RequestDeviceInfo
    rt, client, bridge = _bridge()
    got = []
    rt.submit_action = lambda a: got.append(a)
    bridge.start()
    bridge._on_message(f"superlink/{MH}/refresh/press", "PRESS")
    assert len(got) == 1 and isinstance(got[0], RequestDeviceInfo)
    assert got[0].mac == MAC


def test_buttons_discovery_published_on_adopt():
    from superlink.bridge.events import DeviceStateEvent
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    for name, comp in (("locate", "button"), ("reboot", "button"),
                       ("refresh", "button")):
        cfg = client.find(f"homeassistant/{comp}/{MH}_{name}/config")
        assert cfg is not None, f"missing discovery for {name}"
        payload = json.loads(cfg)
        assert payload["command_topic"] == f"superlink/{MH}/{name}/press"


def test_button_discovery_published_once():
    from superlink.bridge.events import DeviceStateEvent
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    bridge.on_event(DeviceStateEvent(mac=MAC, state="active"))
    cfg_topic = f"homeassistant/button/{MH}_locate/config"
    n = sum(1 for t, _, _ in client.published if t == cfg_topic)
    assert n == 1


def test_active_state_republishes_availability_online():
    # On a reconnect the session emits DeviceStateEvent(active); the bridge must
    # republish device availability as online so HA flips the device back from
    # unavailable after a link drop.
    from superlink.bridge.events import DeviceStateEvent
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(DeviceStateEvent(mac=MAC, state="lost"))
    assert client.find(f"superlink/{MH}/availability") == "offline"
    bridge.on_event(DeviceStateEvent(mac=MAC, state="active"))
    assert client.find(f"superlink/{MH}/availability") == "online"
