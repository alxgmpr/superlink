# SuperLink MQTT / Home Assistant Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in MQTT adapter to `superlink-bridged` that publishes decoded sensor events with Home Assistant MQTT Discovery and turns MQTT commands into bridge actions, running in-process on top of the pure `BridgeCore`.

**Architecture:** A new `bridge/mqtt.py` (`MqttBridge`) + `bridge/entities.py` (HA entity table), plus small additive extensions to C: an `MqttConfig` in `config.py`, a thread-safe `submit_action()` + queue drain in `runtime.py`, and `main()` wiring. MQTT is opt-in via a `mqtt:` config block; with no block the daemon behaves exactly as today.

**Tech Stack:** Python 3.11+, `paho-mqtt`, `PyYAML`, `pytest`. Managed with `uv`.

## Global Constraints

- Python tooling is **`uv` only**; run tests with `uv run pytest tests/... -q` from repo root `/Users/alex/superlink`. Never raw `pip`/`python -m venv`.
- New code under `tools/sx1302/superlink/bridge/`; import as `from superlink.bridge... import ...`. Run pytest from repo root.
- **Do NOT modify sub-project A** (`bridge/core.py`, `session.py`, `store.py`, `profiles.py`, `events.py`, `mapping.py`), `gateway.py`, or `hal.py`. B only extends C's `config.py`/`runtime.py` additively and adds new modules.
- **MQTT is opt-in:** no `mqtt:` block ⇒ `config.mqtt is None` and the daemon + all existing C tests behave exactly as before.
- **Concurrency:** the core is single-threaded (driven from the poll loop). Inbound MQTT callbacks must NOT call `core.submit` directly — they call `runtime.submit_action`, which enqueues; the poll loop drains the queue and calls `core.submit` on the loop thread.
- **Topic scheme:** state `superlink/<machex>/<name>` (retained); command `superlink/<machex>/<name>/set`; adopt `superlink/adopt`; discovered `superlink/discovered/<machex>` (retained); device availability `superlink/<machex>/availability`; bridge LWT `superlink/bridge/availability`. `<machex>` = lowercase hex MAC. `base_topic`/`discovery_prefix` are configurable (defaults `superlink`/`homeassistant`).
- Full suite must stay green except the 2 known-accepted `test_gateway.py` ConnectionChallenge failures. Commit after every task.

---

### Task 1: MqttConfig + `mqtt:` config parsing

**Files:**
- Modify: `tools/sx1302/superlink/bridge/config.py`
- Test: `tests/test_bridge_mqtt_config.py`

**Interfaces:**
- Consumes: existing `RuntimeConfig`.
- Produces:
  - `MqttConfig` dataclass: `host: str`, `port: int = 1883`, `username: str | None = None`, `password: str | None = None`, `base_topic: str = "superlink"`, `discovery_prefix: str = "homeassistant"`, `tls: bool = False`.
  - `RuntimeConfig.mqtt: MqttConfig | None = None` (new field, default None).
  - `RuntimeConfig.load` parses a top-level `mqtt:` block into `MqttConfig` (None when absent; `host` required when present).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_mqtt_config.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_mqtt_config.py -v`
Expected: FAIL with `ImportError: cannot import name 'MqttConfig'`

- [ ] **Step 3: Write the implementation**

In `config.py`, add the dataclass (near the top, after imports) and the field + parsing. Add:

```python
@dataclass
class MqttConfig:
    host: str
    port: int = 1883
    username: str | None = None
    password: str | None = None
    base_topic: str = "superlink"
    discovery_prefix: str = "homeassistant"
    tls: bool = False
```

Add a field to `RuntimeConfig` (after `csv_path`):

```python
    mqtt: "MqttConfig | None" = None
```

In `RuntimeConfig.load`, before the final `return cls(...)`, parse the block:

```python
        mqtt_doc = doc.get("mqtt")
        mqtt = None
        if mqtt_doc is not None:
            if "host" not in mqtt_doc:
                raise ValueError("mqtt block requires 'host'")
            mqtt = MqttConfig(
                host=mqtt_doc["host"],
                port=int(mqtt_doc.get("port", 1883)),
                username=mqtt_doc.get("username"),
                password=mqtt_doc.get("password"),
                base_topic=mqtt_doc.get("base_topic", "superlink"),
                discovery_prefix=mqtt_doc.get("discovery_prefix", "homeassistant"),
                tls=bool(mqtt_doc.get("tls", False)),
            )
```

and add `mqtt=mqtt,` to the `return cls(...)` call.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_mqtt_config.py tests/test_bridge_config.py -v`
Expected: PASS (3 new + the existing config tests).

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/config.py tests/test_bridge_mqtt_config.py
git commit -m "feat: MqttConfig + optional mqtt: config block"
```

---

### Task 2: Thread-safe action seam in BridgeRuntime

**Files:**
- Modify: `tools/sx1302/superlink/bridge/runtime.py`
- Test: `tests/test_bridge_runtime_actions.py`

**Interfaces:**
- Consumes: existing `BridgeRuntime`, `superlink.bridge.events`.
- Produces (added to `BridgeRuntime`): `submit_action(self, action) -> None` (thread-safe enqueue) and `_drain_actions(self) -> None` (pops all, calls `self.core.submit`), called at the top of `poll_once`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_runtime_actions.py
import threading
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore
from superlink.bridge.events import SetProperty
from tests.support.fake_hal import FakeHal

MAC = bytes.fromhex("9041B22E9A53")


def _rt():
    cfg = RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                        pairing_key=DEFAULT_PAIRING_KEY, adopt=ADOPT_ALL)
    return BridgeRuntime(cfg, FakeHal(), store=InMemoryDeviceStore())


def test_submit_action_is_drained_to_core_on_poll():
    rt = _rt()
    got = []
    rt.core.submit = lambda a: got.append(a)
    a = SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=True)
    rt.submit_action(a)
    assert got == []                    # not applied until drained
    rt.poll_once(now=1.0)               # drains at top (no packets needed)
    assert got == [a]


def test_submit_action_thread_safe():
    rt = _rt()
    got = []
    rt.core.submit = lambda a: got.append(a)
    def worker(i):
        rt.submit_action(SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=i))
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    rt.poll_once(now=1.0)
    assert len(got) == 20
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_runtime_actions.py -v`
Expected: FAIL with `AttributeError: 'BridgeRuntime' object has no attribute 'submit_action'`

- [ ] **Step 3: Write the implementation**

In `runtime.py`, add `import queue` at the top. In `BridgeRuntime.__init__`, add (before/after the existing attrs):

```python
        self._action_queue: queue.Queue = queue.Queue()
```

Add two methods:

```python
    def submit_action(self, action) -> None:
        """Thread-safe: enqueue an action to be applied on the poll-loop thread."""
        self._action_queue.put(action)

    def _drain_actions(self) -> None:
        while True:
            try:
                action = self._action_queue.get_nowait()
            except queue.Empty:
                break
            self.core.submit(action)
```

At the very top of `poll_once`, before draining the HAL, call `self._drain_actions()`:

```python
    def poll_once(self, now: float) -> None:
        self._drain_actions()
        for pkt in self.hal.receive():
            ...
```

(Leave the rest of `poll_once` unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_runtime_actions.py tests/test_bridge_runtime_loop.py -v`
Expected: PASS (2 new + the existing loop tests unchanged).

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/runtime.py tests/test_bridge_runtime_actions.py
git commit -m "feat: thread-safe submit_action seam drained on the poll loop"
```

---

### Task 3: HA entity table + discovery config builder

**Files:**
- Create: `tools/sx1302/superlink/bridge/entities.py`
- Test: `tests/test_bridge_entities.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `ENTITY_MAP: dict[str, dict]` — property name → `{component, device_class?, icon?}`.
  - `entity_for(name: str) -> dict | None`.
  - `discovery_config(mac: bytes, name: str, entity: dict, base_topic: str, discovery_prefix: str, unit: str | None) -> tuple[str, dict]` — returns `(config_topic, payload)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_entities.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_entities.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.entities'`

- [ ] **Step 3: Write the implementation**

```python
# tools/sx1302/superlink/bridge/entities.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_entities.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/entities.py tests/test_bridge_entities.py
git commit -m "feat: HA entity mapping table and discovery-config builder"
```

---

### Task 4: MqttBridge

**Files:**
- Create: `tools/sx1302/superlink/bridge/mqtt.py`
- Create: `tests/support/fake_mqtt.py`
- Test: `tests/test_bridge_mqtt.py`

**Interfaces:**
- Consumes: `MqttConfig`, `BridgeRuntime` (`add_event_sink`, `submit_action`), `events`, `entities`.
- Produces:
  - `FakeMqttClient` (test support): `will_set`, `username_pw_set`, `connect`, `subscribe`, `publish`, `loop_start`, `loop_stop`, `disconnect`; records `published: list[(topic, payload, retain)]`, `subscriptions: list[str]`, `lwt: (topic, payload, retain)`.
  - `MqttBridge(config: MqttConfig, runtime, client)` with: `start()`, `stop()`, `on_event(event)`, `_on_message(topic, payload)`.

- [ ] **Step 1: Write the FakeMqttClient support module**

```python
# tests/support/fake_mqtt.py
"""In-memory MQTT client double: records publishes/subscriptions, no broker."""


class FakeMqttClient:
    def __init__(self):
        self.published = []       # list of (topic, payload, retain)
        self.subscriptions = []
        self.lwt = None
        self.connected = False
        self.loop_running = False
        self.on_message = None

    def will_set(self, topic, payload=None, retain=False, qos=0):
        self.lwt = (topic, payload, retain)

    def username_pw_set(self, username, password=None):
        self.auth = (username, password)

    def connect(self, host, port=1883, keepalive=60):
        self.connected = True

    def subscribe(self, topic, qos=0):
        self.subscriptions.append(topic)

    def publish(self, topic, payload=None, qos=0, retain=False):
        self.published.append((topic, payload, retain))

    def loop_start(self):
        self.loop_running = True

    def loop_stop(self):
        self.loop_running = False

    def disconnect(self):
        self.connected = False

    def find(self, topic):
        """Latest payload published to `topic`, or None."""
        for t, p, _ in reversed(self.published):
            if t == topic:
                return p
        return None
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_bridge_mqtt.py
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_mqtt.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.mqtt'`

- [ ] **Step 4: Write the implementation**

```python
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_mqtt.py -v`
Expected: PASS (6 passed)

- [ ] **Step 6: Commit**

```bash
git add tools/sx1302/superlink/bridge/mqtt.py tests/support/fake_mqtt.py tests/test_bridge_mqtt.py
git commit -m "feat: MqttBridge — HA discovery publish + command handling"
```

---

### Task 5: main() wiring, example config, dependency

**Files:**
- Modify: `tools/sx1302/superlink/bridge/runtime.py` (`main()` starts MqttBridge when configured)
- Modify: `tools/sx1302/superlink_bridge.yaml.example` (documented `mqtt:` block)
- Test: `tests/test_bridge_mqtt_wiring.py`

**Interfaces:**
- Produces: a `start_mqtt_if_configured(runtime, config, client=None) -> MqttBridge | None` helper (testable) used by `main()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_mqtt_wiring.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_mqtt_wiring.py -v`
Expected: FAIL with `ImportError: cannot import name 'start_mqtt_if_configured'`

- [ ] **Step 3: Write the implementation**

In `runtime.py`, add the helper (near `build_runtime`):

```python
def start_mqtt_if_configured(runtime, config, client=None):
    """Start the MQTT bridge if config.mqtt is set; return it (or None)."""
    if config.mqtt is None:
        return None
    from .mqtt import MqttBridge
    if client is None:
        import paho.mqtt.client as mqtt
        client = mqtt.Client()
    bridge = MqttBridge(config.mqtt, runtime, client)
    bridge.start()
    return bridge
```

In `main()`, after `runtime = build_runtime(config, SX1302())` and before `runtime.run()`:

```python
    mqtt_bridge = start_mqtt_if_configured(runtime, config)
    try:
        runtime.run()
    finally:
        if mqtt_bridge is not None:
            mqtt_bridge.stop()
```

(If `main()` already calls `runtime.run()` directly, wrap it as shown.)

Add to `superlink_bridge.yaml.example`:

```yaml
# Optional: enable MQTT / Home Assistant. Omit this whole block to disable.
mqtt:
  host: "192.168.1.10"        # MQTT broker
  port: 1883
  username: null
  password: null
  base_topic: "superlink"     # state/command topic root
  discovery_prefix: "homeassistant"   # HA MQTT Discovery prefix
```

- [ ] **Step 4: Install the dependency + run tests**

Run: `uv pip install paho-mqtt && uv run pytest tests/test_bridge_mqtt_wiring.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Full suite**

Run: `uv run pytest tests/ -q`
Expected: only the 2 known-accepted `test_gateway.py` failures fail; everything else green.

- [ ] **Step 6: Commit**

```bash
git add tools/sx1302/superlink/bridge/runtime.py tools/sx1302/superlink_bridge.yaml.example tests/test_bridge_mqtt_wiring.py
git commit -m "feat: wire MqttBridge into the daemon main() (opt-in)"
```

---

## Self-Review

**Spec coverage:**
- Module layout (§Module layout): `mqtt.py` (Task 4), `entities.py` (Task 3), `config.py` MqttConfig (Task 1), `runtime.py` seam + wiring (Tasks 2, 5), example yaml (Task 5). ✅
- HA discovery on generic topics (§decision 1): `discovery_config` + state topics (Tasks 3, 4). ✅
- In-process opt-in (§decision 2): `start_mqtt_if_configured` returns None with no `mqtt:` (Task 5); config None default (Task 1). ✅
- Concurrency/action seam (§decision 3): `submit_action`/`_drain_actions` on the loop (Task 2); inbound handlers call `submit_action`, never `core.submit` (Task 4). ✅
- B-side entity table (§decision 4): `entities.py`, A's profiles untouched (Task 3). ✅
- Adoption UX (§decision 5): `discovered/<mac>` publish + `adopt` command → `AdoptDevice` (Task 4). ✅
- Testing (§Testing): FakeMqttClient (Task 4), state/discovery/discovered/set/adopt/LWT tests (Task 4), thread-safe seam (Task 2), config parsing (Task 1), wiring (Task 5). ✅
- Success criteria: #1 state+discovery once (Task 4 `test_property_event_publishes_state_and_discovery`, `test_discovery_published_once`); #2 set→SetProperty via seam (Task 4 inbound + Task 2 drain); #3 adopt command (Task 4); #4 opt-in (Tasks 1, 5); #5 LWT (Task 4 `test_start_sets_lwt_and_online`); #6 bench (manual). ✅

**Placeholder scan:** none — all steps carry complete code. The `main()` edit (Task 5 Step 3) says "if main already calls run() directly, wrap as shown" — that's a precise instruction against the known current `main()`, not a placeholder.

**Type consistency:** `MqttConfig` fields identical across Tasks 1, 4, 5. `discovery_config(mac, name, entity, base_topic, discovery_prefix, unit)` signature matches between Task 3 definition and Task 4 use. `submit_action`/`_drain_actions` consistent between Task 2 definition and Task 4 use. `MqttBridge(config, runtime, client)`, `on_event`, `_on_message` consistent between Task 4 and Task 5. Topic strings match the Global Constraints scheme throughout. `SetProperty(mac, name_or_id, value)` / `AdoptDevice(mac)` match sub-project A's event dataclasses.

**Note for execution:** Task 4's `_on_message` distinguishes the 2-segment `adopt` topic from the 4-segment `<base>/<mac>/<name>/set` topic by exact match / length; the paho subscription `<base>/+/+/set` only delivers 4-segment set topics, and `<base>/adopt` delivers the adopt topic — so the FakeMqttClient tests inject those shapes directly.
