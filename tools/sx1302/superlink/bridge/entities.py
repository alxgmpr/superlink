"""Property -> Home Assistant entity mapping and discovery-config builder."""
from __future__ import annotations

ENTITY_MAP: dict[str, dict] = {
    "LEAK_DETECTED":        {"component": "binary_sensor", "device_class": "moisture"},
    "MOTION_DETECTED":      {"component": "binary_sensor", "device_class": "motion"},
    "ENTRY_DETECTED":       {"component": "binary_sensor", "device_class": "opening"},
    "TAMPER_DETECTED":      {"component": "binary_sensor", "device_class": "tamper"},
    "GLASS_BREAK_DETECTED": {"component": "binary_sensor", "device_class": "sound"},
    "SMOKE_STATUS":         {"component": "binary_sensor", "device_class": "smoke"},
    "TEMPERATURE":          {"component": "sensor", "device_class": "temperature"},
    "HUMIDITY":             {"component": "sensor", "device_class": "humidity"},
    "BATTERY":              {"component": "sensor", "device_class": "battery"},
    "SIGNAL":               {"component": "sensor", "device_class": "signal_strength"},
    "AMBIENT_LIGHT":        {"component": "sensor", "device_class": "illuminance"},
    "LED_ENABLED":          {"component": "switch"},
}


# Command buttons exposed per adopted device. Each maps a press to a bridge
# Action (wired in mqtt.py). name -> HA button metadata.
COMMAND_BUTTONS: dict[str, dict] = {
    "locate":  {"name": "Locate", "icon": "mdi:map-marker-radius"},
    "reboot":  {"name": "Reboot", "device_class": "restart", "icon": "mdi:restart"},
    "refresh": {"name": "Refresh info", "icon": "mdi:refresh"},
}


# The physical button surfaces as a momentary binary_sensor: the sensor only
# ever reports "pressed" (a last-press uptime that advances), so HA auto-resets
# it to off after `off_delay` seconds rather than waiting for an off report.
PRESS_ENTITY_NAME = "BUTTON"
PRESS_ENTITY: dict = {"component": "binary_sensor", "off_delay": 2}


def entity_for(name: str) -> dict | None:
    return ENTITY_MAP.get(name)


def _device_block(machex: str) -> dict:
    return {
        "identifiers": [machex],
        "name": f"SuperLink {machex}",
        "manufacturer": "Ubiquiti (OpenSuperLink)",
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
        "name": name,
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
    if "off_delay" in entity:
        payload["off_delay"] = entity["off_delay"]
    if unit:
        payload["unit_of_measurement"] = unit
    if component in ("binary_sensor", "switch"):
        payload["payload_on"] = "ON"
        payload["payload_off"] = "OFF"
    if component == "switch":
        payload["command_topic"] = f"{state_topic}/set"
    return config_topic, payload
