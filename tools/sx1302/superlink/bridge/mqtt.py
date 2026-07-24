# tools/sx1302/superlink/bridge/mqtt.py
"""MQTT / Home Assistant adapter: publishes events, handles commands."""
from __future__ import annotations
import json
import logging

from .config import MqttConfig
from .entities import entity_for, discovery_config
from .events import (
    Event, PropertyEvent, DeviceInfoEvent, DeviceDiscovered, DeviceStateEvent,
    SetProperty, AdoptDevice,
)

log = logging.getLogger("superlink.mqtt")


class MqttBridge:
    def __init__(self, config: MqttConfig, runtime, client):
        self.config = config
        self.runtime = runtime
        self.client = client
        self.base = config.base_topic
        self.prefix = config.discovery_prefix
        self._discovery_done: set[str] = set()
        runtime.add_event_sink(self.on_event)

    # --- lifecycle ---
    def start(self) -> None:
        avail = f"{self.base}/bridge/availability"
        self.client.will_set(avail, "offline", retain=True)
        if self.config.username:
            self.client.username_pw_set(self.config.username, self.config.password)
        self.client.on_message = self._paho_on_message
        self.client.connect(self.config.host, self.config.port)
        self.client.subscribe(f"{self.base}/+/+/set")
        self.client.subscribe(f"{self.base}/adopt")
        self.client.loop_start()
        self.client.publish(avail, "online", retain=True)

    def stop(self) -> None:
        self.client.publish(f"{self.base}/bridge/availability", "offline", retain=True)
        self.client.loop_stop()
        self.client.disconnect()

    # --- outbound: events -> MQTT ---
    def on_event(self, event: Event) -> None:
        if isinstance(event, PropertyEvent):
            self._publish_property(event)
        elif isinstance(event, DeviceDiscovered):
            self.client.publish(f"{self.base}/discovered/{event.mac.hex()}",
                                json.dumps({"channel": event.channel,
                                            "first_seen": event.first_seen}),
                                retain=True)
        elif isinstance(event, DeviceStateEvent):
            state = "online" if event.state in ("adopted", "active") else "offline"
            self.client.publish(f"{self.base}/{event.mac.hex()}/availability",
                                state, retain=True)

    def _publish_property(self, ev: PropertyEvent) -> None:
        machex = ev.mac.hex()
        entity = entity_for(ev.name)
        if entity is not None:
            key = f"{machex}_{ev.name}"
            if key not in self._discovery_done:
                topic, payload = discovery_config(ev.mac, ev.name, entity,
                                                  self.base, self.prefix, ev.unit)
                self.client.publish(topic, json.dumps(payload), retain=True)
                self._discovery_done.add(key)
        if ev.decoded and isinstance(ev.value, bool):
            value = "ON" if ev.value else "OFF"
        elif ev.decoded and ev.value is not None:
            value = str(ev.value)
        else:
            value = ev.raw.hex()
        self.client.publish(f"{self.base}/{machex}/{ev.name}", value, retain=True)

    # --- inbound: MQTT -> actions ---
    def _paho_on_message(self, client, userdata, msg):
        payload = msg.payload.decode() if isinstance(msg.payload, bytes) else msg.payload
        self._on_message(msg.topic, payload)

    def _on_message(self, topic: str, payload: str) -> None:
        parts = topic.split("/")
        if topic == f"{self.base}/adopt":
            try:
                mac = bytes.fromhex(payload.strip())
            except ValueError:
                log.warning("bad adopt payload: %r", payload)
                return
            self.runtime.submit_action(AdoptDevice(mac=mac))
            return
        # <base>/<machex>/<name>/set
        if len(parts) == 4 and parts[0] == self.base and parts[3] == "set":
            try:
                mac = bytes.fromhex(parts[1])
            except ValueError:
                return
            name = parts[2]
            self.runtime.submit_action(SetProperty(mac=mac, name_or_id=name,
                                                   value=_parse_value(payload)))


def _parse_value(payload: str):
    p = payload.strip()
    if p.upper() in ("ON", "TRUE", "1"):
        return True
    if p.upper() in ("OFF", "FALSE", "0"):
        return False
    try:
        return int(p)
    except ValueError:
        try:
            return float(p)
        except ValueError:
            return p
