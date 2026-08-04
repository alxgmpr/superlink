from superlink.bridge.entities import (
    ENTITY_MAP, PRESS_ENTITY, PRESS_ENTITY_NAME, entity_for, discovery_config,
    friendly_name,
)

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
    assert payload["name"] == "Leak"                # not the ALL_CAPS id
    assert payload["unique_id"] == "9041b22e9a53_LEAK_DETECTED"
    assert payload["object_id"] == "9041b22e9a53_LEAK_DETECTED"
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


def test_every_mapped_entity_has_a_human_name():
    """No entity should reach HA displayed as a raw ALL_CAPS property id."""
    for name, entity in list(ENTITY_MAP.items()) + [(PRESS_ENTITY_NAME,
                                                     PRESS_ENTITY)]:
        display = friendly_name(name, entity)
        assert display == entity["name"]
        assert display != name
        assert "_" not in display
        assert display[0].isupper()


def test_friendly_name_falls_back_to_sentence_case():
    assert friendly_name("AMBIENT_LIGHT", {}) == "Ambient light"
    assert friendly_name("SOME_NEW_PROPERTY", {"component": "sensor"}) \
        == "Some new property"
