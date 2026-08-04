"""Property -> Home Assistant entity mapping and discovery-config builder."""
from __future__ import annotations

# `name` is the human-facing HA entity name (sentence case, per the HA style
# guide) — the raw ALL_CAPS property id is kept only as the unique_id/object_id
# and the MQTT topic segment, so entity_ids stay stable.
ENTITY_MAP: dict[str, dict] = {
    "LEAK_DETECTED":        {"component": "binary_sensor", "device_class": "moisture", "name": "Leak"},
    "MOTION_DETECTED":      {"component": "binary_sensor", "device_class": "motion", "name": "Motion"},
    "ENTRY_DETECTED":       {"component": "binary_sensor", "device_class": "opening", "name": "Door"},
    "TAMPER_DETECTED":      {"component": "binary_sensor", "device_class": "tamper", "name": "Tamper"},
    "GLASS_BREAK_DETECTED": {"component": "binary_sensor", "device_class": "sound", "name": "Glass break"},
    "SMOKE_STATUS":         {"component": "binary_sensor", "device_class": "smoke", "name": "Smoke"},
    "TEMPERATURE":          {"component": "sensor", "device_class": "temperature", "name": "Temperature"},
    "HUMIDITY":             {"component": "sensor", "device_class": "humidity", "name": "Humidity"},
    "BATTERY":              {"component": "sensor", "device_class": "battery", "name": "Battery"},
    "BATTERY_VOLTAGE":      {"component": "sensor", "device_class": "voltage", "name": "Battery voltage",
                             "precision": 3, "state_class": "measurement"},
    "SIGNAL":               {"component": "sensor", "device_class": "signal_strength", "name": "Signal"},
    "AMBIENT_LIGHT":        {"component": "sensor", "device_class": "illuminance", "name": "Ambient light"},
    "LED_ENABLED":          {"component": "switch", "name": "LED"},
}


# Command buttons exposed per adopted device. Each maps a press to a bridge
# Action (wired in mqtt.py). name -> HA button metadata.
COMMAND_BUTTONS: dict[str, dict] = {
    "locate":  {"name": "Locate", "icon": "mdi:map-marker-radius"},
    "reboot":  {"name": "Reboot", "device_class": "restart", "icon": "mdi:restart"},
    "refresh": {"name": "Refresh info", "icon": "mdi:refresh"},
    "clear_tamper": {"name": "Clear tamper", "icon": "mdi:shield-refresh"},
}


# The physical button has no discrete "off" — the sensor only ever reports a
# press (a last-press uptime that advances). It surfaces as an HA `event` entity
# (a press trigger HA timestamps), not an on/off binary_sensor.
PRESS_ENTITY_NAME = "BUTTON"
PRESS_ENTITY: dict = {"component": "event", "event_types": ["press"],
                      "name": "Button"}


def entity_for(name: str) -> dict | None:
    return ENTITY_MAP.get(name)


def friendly_name(name: str, entity: dict) -> str:
    """Display name for an entity: the curated one, else the property id
    de-underscored and sentence-cased (AMBIENT_LIGHT -> "Ambient light")."""
    if entity.get("name"):
        return entity["name"]
    words = name.replace("_", " ").strip().lower()
    return words[:1].upper() + words[1:]


def _device_block(machex: str) -> dict:
    return {
        "identifiers": [machex],
        "name": f"SuperLink {machex}",
        "manufacturer": "Ubiquiti (superlink2mqtt)",
        "model": "SuperLink sensor",
    }


def button_discovery_config(mac: bytes, name: str, base_topic: str,
                            discovery_prefix: str):
    """HA MQTT-discovery config for a command button (LOCATE/REBOOT/refresh)."""
    machex = mac.hex()
    uid = f"{machex}_{name}"
    meta = COMMAND_BUTTONS[name]
    payload = {
        "name": meta["name"],
        "unique_id": uid,
        "object_id": uid,
        "command_topic": f"{base_topic}/{machex}/{name}/press",
        "payload_press": "PRESS",
        "availability_topic": f"{base_topic}/{machex}/availability",
        "payload_available": "online",
        "payload_not_available": "offline",
        "device": _device_block(machex),
    }
    if "icon" in meta:
        payload["icon"] = meta["icon"]
    if "device_class" in meta:
        payload["device_class"] = meta["device_class"]
    config_topic = f"{discovery_prefix}/button/{uid}/config"
    return config_topic, payload


def discovery_config(mac: bytes, name: str, entity: dict, base_topic: str,
                     discovery_prefix: str, unit: str | None):
    machex = mac.hex()
    component = entity["component"]
    uid = f"{machex}_{name}"
    state_topic = f"{base_topic}/{machex}/{name}"
    avail_topic = f"{base_topic}/{machex}/availability"
    config_topic = f"{discovery_prefix}/{component}/{uid}/config"

    payload = {
        "name": friendly_name(name, entity),
        "unique_id": uid,
        "object_id": uid,
        "state_topic": state_topic,
        "availability_topic": avail_topic,
        "payload_available": "online",
        "payload_not_available": "offline",
        "device": _device_block(machex),
    }
    if "device_class" in entity:
        payload["device_class"] = entity["device_class"]
    if "icon" in entity:
        payload["icon"] = entity["icon"]
    # HA rounds to 0 decimals by default for most device classes, which turns
    # 2.986 V into "3 V". Entities with sub-unit resolution must say so.
    if "precision" in entity:
        payload["suggested_display_precision"] = entity["precision"]
    if "state_class" in entity:
        payload["state_class"] = entity["state_class"]
    if unit:
        payload["unit_of_measurement"] = unit
    if component in ("binary_sensor", "switch"):
        payload["payload_on"] = "ON"
        payload["payload_off"] = "OFF"
    if component == "switch":
        payload["command_topic"] = f"{state_topic}/set"
    if component == "event":
        payload["event_types"] = entity.get("event_types", [])
    return config_topic, payload
