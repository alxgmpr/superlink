# tools/sx1302/superlink/bridge/mqtt.py
"""MQTT / Home Assistant adapter: publishes events, handles commands."""
from __future__ import annotations
import json
import logging

from .config import MqttConfig
from .entities import (
    entity_for, discovery_config, button_discovery_config, COMMAND_BUTTONS,
)
from .events import (
    Event, PropertyEvent, DeviceInfoEvent, DeviceDiscovered, DeviceStateEvent,
    SetProperty, AdoptDevice, Locate, Reboot, RequestDeviceInfo,
)

# Command-button name -> factory building the Action from a device MAC.
_BUTTON_ACTIONS = {
    "locate": lambda mac: Locate(mac=mac),
    "reboot": lambda mac: Reboot(mac=mac),
    "refresh": lambda mac: RequestDeviceInfo(mac=mac),
}

log = logging.getLogger("superlink.mqtt")


class MqttBridge:
    def __init__(self, config: MqttConfig, runtime, client):
        self.config = config
        self.runtime = runtime
        self.client = client
        self.base = config.base_topic
        self.prefix = config.discovery_prefix
        self._discovery_done: set[str] = set()
        self._buttons_done: set[bytes] = set()   # macs with button discovery sent
        runtime.add_event_sink(self.on_event)

    # --- lifecycle ---
    def start(self) -> None:
        avail = f"{self.base}/bridge/availability"
        self.client.will_set(avail, "offline", retain=True)
        if self.config.username:
            self.client.username_pw_set(self.config.username, self.config.password)
        self.client.on_message = self._paho_on_message
        self.client.on_connect = self._paho_on_connect
        self.client.connect(self.config.host, self.config.port)
        self.client.loop_start()
        self.client.publish(avail, "online", retain=True)

    def _paho_on_connect(self, client, userdata, flags, reason_code,
                         properties=None):
        # (Re)subscribe on every (re)connect. paho does not restore
        # subscriptions after an auto-reconnect, and subscribing here (rather
        # than right after connect()) guarantees it happens post-CONNACK — so
        # HA command topics keep working across broker blips.
        client.subscribe(f"{self.base}/+/+/set")
        client.subscribe(f"{self.base}/+/+/press")
        client.subscribe(f"{self.base}/adopt")
        log.info("MQTT connected (rc=%s); subscribed to command topics",
                 reason_code)

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
            if event.state in ("adopted", "active"):
                self._publish_buttons(event.mac)
            self.client.publish(f"{self.base}/{event.mac.hex()}/availability",
                                state, retain=True)

    def _publish_buttons(self, mac: bytes) -> None:
        """Publish LOCATE/REBOOT/refresh button discovery once per device."""
        if mac in self._buttons_done:
            return
        self._buttons_done.add(mac)
        for name in COMMAND_BUTTONS:
            topic, payload = button_discovery_config(
                mac, name, self.base, self.prefix)
            self.client.publish(topic, json.dumps(payload), retain=True)

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
        log.info("MQTT RX %s = %r", msg.topic, payload)
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
        # <base>/<machex>/<name>/{set,press}
        if len(parts) == 4 and parts[0] == self.base:
            try:
                mac = bytes.fromhex(parts[1])
            except ValueError:
                return
            name, action = parts[2], parts[3]
            if action == "set":
                self.runtime.submit_action(SetProperty(
                    mac=mac, name_or_id=name, value=_parse_value(payload)))
            elif action == "press":
                factory = _BUTTON_ACTIONS.get(name)
                if factory is None:
                    log.warning("unknown button %r", name)
                    return
                self.runtime.submit_action(factory(mac))


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
