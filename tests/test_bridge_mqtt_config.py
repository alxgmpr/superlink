import pytest
from superlink.bridge.config import RuntimeConfig, MqttConfig

BASE = 'gw_mac: "010203040506"\nadopt: all\n'
WITH_MQTT = BASE + """
mqtt:
  host: "192.168.1.10"
  username: "u"
  password: "p"
  base_topic: "slink"
"""


def _w(tmp_path, text):
    p = tmp_path / "c.yaml"; p.write_text(text); return str(p)


def test_no_mqtt_block_is_none(tmp_path):
    c = RuntimeConfig.load(_w(tmp_path, BASE))
    assert c.mqtt is None


def test_mqtt_block_parsed(tmp_path):
    c = RuntimeConfig.load(_w(tmp_path, WITH_MQTT))
    assert isinstance(c.mqtt, MqttConfig)
    assert c.mqtt.host == "192.168.1.10"
    assert c.mqtt.port == 1883                      # default
    assert c.mqtt.username == "u" and c.mqtt.password == "p"
    assert c.mqtt.base_topic == "slink"
    assert c.mqtt.discovery_prefix == "homeassistant"  # default


def test_mqtt_requires_host(tmp_path):
    with pytest.raises((KeyError, ValueError)):
        RuntimeConfig.load(_w(tmp_path, BASE + "mqtt:\n  port: 1883\n"))
