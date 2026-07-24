from superlink.bridge.entities import ENTITY_MAP, entity_for, discovery_config

MAC = bytes.fromhex("9041B22E9A53")


def test_entity_lookup():
    assert entity_for("LEAK_DETECTED")["component"] == "binary_sensor"
    assert entity_for("LEAK_DETECTED")["device_class"] == "moisture"
    assert entity_for("NOPE") is None


def test_discovery_config_binary_sensor():
    topic, payload = discovery_config(MAC, "LEAK_DETECTED",
                                      ENTITY_MAP["LEAK_DETECTED"],
                                      base_topic="superlink",
                                      discovery_prefix="homeassistant", unit=None)
    assert topic == "homeassistant/binary_sensor/9041b22e9a53_LEAK_DETECTED/config"
    assert payload["state_topic"] == "superlink/9041b22e9a53/LEAK_DETECTED"
    assert payload["device_class"] == "moisture"
    assert payload["payload_on"] == "ON" and payload["payload_off"] == "OFF"
    assert payload["unique_id"] == "9041b22e9a53_LEAK_DETECTED"
    assert payload["availability_topic"] == "superlink/9041b22e9a53/availability"
    assert payload["device"]["identifiers"] == ["9041b22e9a53"]
    assert "command_topic" not in payload           # not a switch


def test_discovery_config_switch_has_command_topic():
    topic, payload = discovery_config(MAC, "LED_ENABLED", ENTITY_MAP["LED_ENABLED"],
                                      base_topic="superlink",
                                      discovery_prefix="homeassistant", unit=None)
    assert topic == "homeassistant/switch/9041b22e9a53_LED_ENABLED/config"
    assert payload["command_topic"] == "superlink/9041b22e9a53/LED_ENABLED/set"


def test_discovery_config_sensor_unit():
    topic, payload = discovery_config(MAC, "TEMPERATURE", ENTITY_MAP["TEMPERATURE"],
                                      base_topic="superlink",
                                      discovery_prefix="homeassistant", unit="°C")
    assert topic == "homeassistant/sensor/9041b22e9a53_TEMPERATURE/config"
    assert payload["unit_of_measurement"] == "°C"
    assert payload["device_class"] == "temperature"
