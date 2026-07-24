# SuperLink MQTT / Home Assistant Adapter — Design Spec

**Date:** 2026-07-24
**Status:** Draft
**Scope:** Sub-project B of the open SuperLink bridge — an opt-in MQTT adapter
that publishes decoded sensor events (with Home Assistant MQTT Discovery) and
turns MQTT commands into bridge actions, running in-process inside the
`superlink-bridged` daemon (sub-project C) on top of the pure `BridgeCore`
(sub-project A).

## Goal

Let someone run their own Ubiquiti SuperLink system from Home Assistant (or any
MQTT app): adopted sensors auto-appear in HA as entities (leak, motion,
temperature, battery, door, LED switch, …), their state updates live, and HA
controls/commands flow back to the sensors — with no manual HA YAML. This
completes the A → C → B arc into an end-to-end product.

### Non-goals (deferred)

- Any protocol/wire change or new RE. B is pure northbound translation.
- Per-device HA "Adopt" button entities (discovery-of-discovery). B exposes a
  discovery topic + an adopt command instead; the button is later polish.
- Friendly per-device names / rename UX. Device id is the sensor MAC in v1.
- Non-MQTT northbounds (REST, WebSocket). MQTT only.

## Context: what already exists

- **A (`main`):** `BridgeCore` (pure), event/action dataclasses
  (`PropertyEvent`, `DeviceInfoEvent`, `DeviceDiscovered`, `DeviceStateEvent`;
  `SetProperty`, `AdoptDevice`, …), `ProfileRegistry` (decoded value + unit).
- **C (`main`):** `BridgeRuntime` owns the SX1302 + RX-driven poll loop and
  exposes `add_event_sink(callback)` (events OUT). It has **no inbound action
  path** yet — `core.submit` is called only internally for auto-adopt.
  `RuntimeConfig` is YAML-loaded. `main()` builds a real `SX1302` and runs.

## Architectural decisions (settled during brainstorming)

1. **HA depth:** full **HA MQTT Discovery** layered on a **generic topic
   scheme** — serves both HA (auto entities) and plain-MQTT users from one
   design.
2. **Packaging:** **in-process module** activated by an optional `mqtt:` config
   block. No `mqtt:` ⇒ the daemon behaves exactly as C does today.
3. **Concurrency:** paho runs its own network thread; inbound command callbacks
   enqueue actions via a new thread-safe `runtime.submit_action(action)`, and the
   **poll loop drains the queue** and calls `core.submit` on the loop thread —
   `BridgeCore`/`DeviceSession` stay single-threaded. Outbound `publish()` is
   called from the loop thread (paho publish is thread-safe).
4. **Entity mapping:** a **B-side table** (`entities.py`) maps property name → HA
   `{component, device_class, icon}`. Sub-project A's profile file stays
   protocol-only; `unit`/`value` come from the `PropertyEvent`.
5. **Adoption UX:** **discovery topic + adopt command** — publish each
   `DeviceDiscovered` MAC to a retained topic; accept a MAC on an adopt command
   topic and submit `AdoptDevice`. Live, no-restart adoption from HA / any MQTT
   client.

## Module layout

| Module | Role |
|--------|------|
| `tools/sx1302/superlink/bridge/mqtt.py` | `MqttBridge` — paho client; publishes state + HA discovery; handles command/adopt topics. |
| `tools/sx1302/superlink/bridge/entities.py` | Property→HA entity table + a helper to build a discovery-config dict. |
| `tools/sx1302/superlink/bridge/config.py` | **Extended**: optional `MqttConfig` (parsed from a `mqtt:` block). |
| `tools/sx1302/superlink/bridge/runtime.py` | **Extended**: `submit_action()` + thread-safe queue drained in the loop; `main()` starts `MqttBridge` when configured. |
| `tools/sx1302/superlink_bridge.yaml.example` | **Extended**: documented `mqtt:` block. |

New dependency: `paho-mqtt`.

## Component design

### `MqttConfig` (in `config.py`)

Parsed from an optional `mqtt:` block; `RuntimeConfig.mqtt: MqttConfig | None`
(None when absent). Fields: `host`, `port=1883`, `username=None`,
`password=None`, `base_topic="superlink"`, `discovery_prefix="homeassistant"`,
`tls=False`. `RuntimeConfig.load` sets `mqtt=None` when there is no `mqtt:` key.

### Action seam in `BridgeRuntime` (the C extension)

- `submit_action(self, action) -> None`: append to a `queue.Queue` (thread-safe).
  Callable from any thread.
- `_drain_actions(self) -> None`: pop all queued actions and `self.core.submit(a)`
  for each; called at the top of `poll_once` (and once per `run` iteration) so
  actions execute on the loop thread. Existing behavior otherwise unchanged; when
  no MQTT is configured the queue is simply always empty.

### `entities.py`

```python
# name -> {component, device_class, icon}
ENTITY_MAP = {
  "LEAK_DETECTED":  {"component": "binary_sensor", "device_class": "moisture"},
  "MOTION_DETECTED":{"component": "binary_sensor", "device_class": "motion"},
  "ENTRY_DETECTED": {"component": "binary_sensor", "device_class": "opening"},
  "TAMPER_DETECTED":{"component": "binary_sensor", "device_class": "tamper"},
  "GLASS_BREAK_DETECTED": {"component": "binary_sensor", "device_class": "sound"},
  "SMOKE_STATUS":   {"component": "binary_sensor", "device_class": "smoke"},
  "TEMPERATURE":    {"component": "sensor", "device_class": "temperature"},
  "HUMIDITY":       {"component": "sensor", "device_class": "humidity"},
  "BATTERY":        {"component": "sensor", "device_class": "battery"},
  "SIGNAL":         {"component": "sensor", "device_class": "signal_strength"},
  "AMBIENT_LIGHT":  {"component": "sensor", "device_class": "illuminance"},
  "LED_ENABLED":    {"component": "switch"},
}
```

`discovery_config(mac, name, entity, base_topic, unit) -> (topic, payload_dict)`
builds the retained HA config: `unique_id`/`object_id = <machex>_<name>`,
`state_topic`, `command_topic` (only for `switch`), `device_class`,
`unit_of_measurement` (from the event's `unit`), `availability_topic`,
`payload_on/off` for binary_sensor/switch, and a `device` block
`{identifiers: [machex], name: "SuperLink <machex>", manufacturer, model}` so all
of a sensor's entities group under one HA device. Discovery topic:
`<discovery_prefix>/<component>/<machex>_<name>/config`.

### `MqttBridge` (`mqtt.py`)

`MqttBridge(mqtt_config, runtime, client=None, base_topic=..., discovery_prefix=...)`
— `client` injectable (a `FakeMqttClient` in tests). Holds a `runtime` ref for
`submit_action`, and registers `self.on_event` via `runtime.add_event_sink`.

- `start()`: set LWT on `<base>/bridge/availability` = `offline` (retained),
  connect, subscribe `<base>/+/+/set` and `<base>/adopt`, start the paho network
  loop (own thread), publish bridge availability `online` (retained).
- `on_event(event)` (called on the loop thread):
  - `DeviceInfoEvent` → remember `device_type`/version; mark device seen.
  - `PropertyEvent` → if the property has an entity mapping and its discovery
    config hasn't been published, publish it (retained); then publish the value
    to `<base>/<machex>/<name>` (retained) — decoded `value` (bool → `ON`/`OFF`),
    or raw hex when `decoded=False`.
  - `DeviceDiscovered` → publish retained `<base>/discovered/<machex>` (payload:
    channel/first_seen).
  - `DeviceStateEvent` → publish `<base>/<machex>/availability`
    (`online` for adopted/active, `offline` for lost).
- `_on_message(topic, payload)` (paho thread):
  - `<base>/<machex>/<name>/set` → parse payload to a value (`ON`/`OFF`→bool,
    else int/float/str per the entity), `runtime.submit_action(SetProperty(mac,
    name, value))`.
  - `<base>/adopt` → payload is a MAC hex → `runtime.submit_action(AdoptDevice(mac))`.
- `stop()`: publish bridge availability `offline`, disconnect, stop loop.

### `main()` wiring (C extension)

After building the runtime, if `config.mqtt` is set: construct `MqttBridge(config.mqtt,
runtime)`, call `start()`, and ensure `stop()` on shutdown. MQTT stays opt-in.

## Testing strategy

A `FakeMqttClient` records `publish(topic, payload, retain)` calls, tracks
`subscribe` topics, and lets tests inject `_on_message(topic, payload)`; no broker
needed. `paho-mqtt` installed via `uv`.

- **State publish:** a `PropertyEvent(BATTERY=100)` → retained publish to
  `superlink/<machex>/BATTERY` payload `100`; a bool `LEAK_DETECTED=True` →
  `ON`.
- **Discovery:** first `PropertyEvent`/`DeviceInfoEvent` for a mapped property →
  retained config to `homeassistant/binary_sensor/<machex>_LEAK_DETECTED/config`
  with `device_class: moisture`, correct `state_topic`, and the `device` block;
  published once (not re-published every event).
- **Unmapped property:** still publishes state, no discovery config.
- **Discovered:** `DeviceDiscovered` → retained `superlink/discovered/<machex>`.
- **Inbound set:** injected `superlink/<machex>/LED_ENABLED/set` = `ON` →
  `runtime.submit_action` receives `SetProperty(mac, "LED_ENABLED", True)`.
- **Inbound adopt:** injected `superlink/adopt` = `<machex>` →
  `AdoptDevice(mac)` submitted.
- **Thread-safe seam (C extension):** `runtime.submit_action(a)` enqueues;
  `poll_once`/`_drain_actions` calls `core.submit(a)` on the loop thread; existing
  runtime tests stay green with no `mqtt:` configured.
- **Config:** `mqtt:` block → `MqttConfig`; absent → `mqtt is None`.
- **Availability/LWT:** `start()` sets the LWT and publishes `online`; `stop()`
  publishes `offline`.
- **Manual bench:** point at a real broker + Home Assistant; confirm a real
  sensor's entities appear and a command round-trips. (Not automated.)

## Success criteria

1. An adopted sensor's `PropertyEvent`s publish retained state to
   `superlink/<mac>/<name>` and, for mapped properties, HA discovery config so the
   entities auto-appear in Home Assistant — discovery published once per entity.
2. An HA/MQTT `set` command on a `switch` property round-trips to a
   `SetProperty` action via the thread-safe seam, executed on the core's loop
   thread.
3. Publishing a MAC to `<base>/adopt` adopts that device live (no restart).
4. MQTT is fully opt-in: with no `mqtt:` block, the daemon and all existing C
   tests behave exactly as before.
5. Bridge availability reflects daemon liveness via MQTT LWT (`offline` if the
   daemon dies).
6. Real broker + HA bench validation (manual).
