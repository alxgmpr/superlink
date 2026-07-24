"""Property -> Home Assistant entity mapping and discovery-config builder."""
from __future__ import annotations

ENTITY_MAP: dict[str, dict] = {
    "LEAK_DETECTED":        {"component": "binary_sensor", "device_class": "moisture"},
    "MOTION_DETECTED":      {"component": "binary_sensor", "device_class": "motion"},
    "ENTRY_DETECTED":       {"component": "binary_sensor", "device_class": "opening"},
    "TAMPER_DETECTED":      {"component": "binary_sensor", "device_class": "tamper"},
    "GLASS_BREAK_DETECTED": {"component": "binary_sensor", "device_class": "sound"},
    "SMOKE_STATUS":         {"component": "binary_sensor", "device_class": "smoke"},
    "BUTTON_PRESSED":       {"component": "binary_sensor"},
    "TEMPERATURE":          {"component": "sensor", "device_class": "temperature"},
    "HUMIDITY":             {"component": "sensor", "device_class": "humidity"},
    "BATTERY":              {"component": "sensor", "device_class": "battery"},
    "SIGNAL":               {"component": "sensor", "device_class": "signal_strength"},
    "AMBIENT_LIGHT":        {"component": "sensor", "device_class": "illuminance"},
    "LED_ENABLED":          {"component": "switch"},
}


def entity_for(name: str) -> dict | None:
    return ENTITY_MAP.get(name)


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
        "device": {
            "identifiers": [machex],
            "name": f"SuperLink {machex}",
            "manufacturer": "Ubiquiti (OpenSuperLink)",
            "model": "SuperLink sensor",
        },
    }
    if "device_class" in entity:
        payload["device_class"] = entity["device_class"]
    if "icon" in entity:
        payload["icon"] = entity["icon"]
    if unit:
        payload["unit_of_measurement"] = unit
    if component in ("binary_sensor", "switch"):
        payload["payload_on"] = "ON"
        payload["payload_off"] = "OFF"
    if component == "switch":
        payload["command_topic"] = f"{state_topic}/set"
    return config_topic, payload
