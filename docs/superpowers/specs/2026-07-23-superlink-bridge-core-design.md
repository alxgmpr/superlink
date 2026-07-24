# SuperLink Protocol/Bridge Core — Design Spec

**Date:** 2026-07-23
**Status:** Draft
**Scope:** Sub-project A of the open SuperLink bridge — a transport- and
interface-agnostic protocol engine that turns decrypted SuperLink frames into
typed events and typed actions into outgoing frames, for N sensors.

## Goal

Give the OpenSuperLink project a clean, reusable core that a northbound adapter
(MQTT / Home Assistant, sub-project B) and a runtime daemon (SX1302 HAL + loop,
sub-project C) can sit on top of. This is the layer that lets someone run their
own Ubiquiti SuperLink system on their own hardware: pair sensors, receive their
events, and command them — all from an API that knows nothing about the radio or
about MQTT.

This spec covers **only** the core engine. MQTT and the daemon are separate
specs built on this one.

### Non-goals (deferred to later sub-projects)

- MQTT / Home Assistant discovery topics (sub-project B).
- The runtime daemon: owning the SX1302 HAL, the poll loop, config loading, and
  wiring core ↔ radio ↔ MQTT (sub-project C).
- Any new RF/crypto/protocol reverse engineering. The core restructures the
  already-working protocol; it does not change wire behavior.

## Context: what already exists

- `hal.py` — SX1302 HAL (RX/TX). Owned by the runtime, not the core.
- `decoder.py` / `crypto.py` — frame parse, XSalsa20-Poly1305, BLAKE2b KDF.
- `appmsg.py` — application-layer codec: `MessageId`, `PROPERTY_NAMES` (~42 ids),
  `decode_message`, `property_sizes`, and probe encoders.
- `gateway.py` — a 1170-line **single-session** state machine
  (`IDLE→BEACONING→DH_EXCHANGE→CHALLENGE→SETUP→ACTIVE`) tangled together with
  RE/fuzzing logic (`sweep`, property probes, adoption-key capture). Pairing and
  adoption work end-to-end against real sensors.

The RF and crypto plumbing is done. What is missing is the *bridge* layer: a
clean event/action translation engine, multi-device management, and a
well-defined public interface. `gateway.py`'s reports currently route straight
into the RE `sweep` (`_ingest_app_report`); the product path needs that same
decrypted message surfaced as a typed event instead.

## Architectural decisions (settled during brainstorming)

1. **Scope:** protocol/bridge core only (sub-project A).
2. **Relationship to `gateway.py`:** extract & refactor. One authoritative
   session engine; the RE tooling becomes a consumer of the same public API.
3. **I/O boundary:** the core is a **pure engine** — no I/O, no threads. A
   runtime pumps it. Time is injected (`now: float` passed in) so beacon/timeout
   logic is deterministic and testable without hardware.
4. **Device lifecycle:** the core owns the **full, multi-device** lifecycle —
   pairing/adoption as an action, steady-state keepalive, per-device events.
   Key/registry persistence goes through a storage **interface** the core
   defines but does not implement.
5. **Event/action semantics:** **layered**. The core always emits a faithful
   structured event and *also* decodes a typed value via a per-property /
   per-device-type profile table when the encoding is known; unknown encodings
   pass through raw with `decoded=false`. Actions mirror this with a raw escape
   hatch. Profiles live in a **YAML data file**, not code.

## Module layout

New subpackage `tools/sx1302/superlink/bridge/`:

| Module | Role |
|--------|------|
| `session.py` | `DeviceSession` — per-sensor lifecycle state machine, extracted from `gateway.py`. |
| `core.py` | `BridgeCore` — multi-device orchestrator + the pump API. |
| `events.py` | Event and action dataclasses. |
| `profiles.py` | `ProfileRegistry` — loads and applies the decode/encode table. |
| `profiles/superlink.yaml` | Property / device-type decode table (data, not code). |
| `store.py` | `DeviceStore` interface + a bundled JSON-file implementation. |

`hal.py`, `decoder.py`, `crypto.py`, `appmsg.py` are unchanged dependencies.

## Component design

### `DeviceSession` (one per sensor)

Lifts the working state machine out of `gateway.py` with **no protocol change** —
same states, same DH/challenge/adoption/reconnect handling, same sequence
counters. Owns `session_key`, `transport_key`, `kdf_context`, seq counters, and
its `State`. Pure: methods take `now: float` and return `(frames_to_send,
events_to_emit)`. Contains **no** RE/sweep code.

Responsibilities:
- Drive the handshake for a joining sensor (beacon → DH → challenge → setup →
  active) and the adopted/reconnect path (KDF ctx = primary addDevice key,
  transport = fallback key), exactly as `gateway.py` does today.
- In ACTIVE, decrypt UL frames, hand the app-message body up to `BridgeCore`,
  and build DL replies for queued actions.
- Emit beacons/keepalives when `now` says they are due.

### `BridgeCore` (the public interface)

Pure engine, no I/O, no threads. Holds `{mac: DeviceSession}`.

```
feed(raw: bytes, channel: int, now: float) -> list[OutgoingFrame]
    Pump one received frame. Route to the owning DeviceSession by MAC
    (or the pairing session for an unadopted joiner). Decode any app
    message into events and dispatch to subscribers. Return frames to TX.

tick(now: float) -> list[OutgoingFrame]
    Beacons, keepalives, and session timeouts across all devices.

submit(action: Action) -> None
    Queue a high-level action; it is encoded and TX'd on that device's
    next DL window.

subscribe(callback: Callable[[Event], None]) -> None
    Register an event sink. Called synchronously from feed()/tick().
```

`OutgoingFrame = {data: bytes, freq_hz: int, channel: int}` — mirrors today's
`(tx_data, tx_freq_hz)` return so the runtime loop is a thin adapter.

Pairing is an action (`BeginPairing`) that opens a join window; a joining sensor
gets a new `DeviceSession`, and on commit its `DeviceRecord` is saved through the
store.

### Events & actions (`events.py`, dataclasses)

Events (core → consumer):
- `PropertyEvent(mac, property_id, name, channel, raw, value, unit, decoded)`
- `DeviceInfoEvent(mac, device_type, fw_version, hw_revision, anon_id,
  supported_message_ids, supported_properties)`
- `DeviceStateEvent(mac, state)` where state ∈ `pairing | adopted | active | lost`
- `RawMessageEvent(mac, message_id, body)` — catch-all for messages without a
  higher-level mapping.

Actions (consumer → core):
- `SetProperty(mac, name_or_id, value)` — encoded via the profile table.
- `SetPropertyRaw(mac, property_id, channel, raw)` — escape hatch.
- `RequestProperty(mac, ids)`, `RequestDeviceInfo(mac)`
- `Locate(mac)`, `Reboot(mac)`, `FactoryReset(mac)`, `Ping(mac, data=b"")`
- `BeginPairing(timeout)`

### `ProfileRegistry` + `superlink.yaml`

`superlink.yaml` maps each property id to `{name, type, scale, unit, access}`
with optional per-`deviceType` overrides. Example intent:

```yaml
properties:
  3:  { name: BATTERY,      type: u8,   unit: "%" }
  7:  { name: TEMPERATURE,  type: s16,  scale: 0.1, unit: "°C" }
  4:  { name: LEAK_DETECTED, type: bool }
  14: { name: LED_ENABLED,  type: bool, access: rw }
device_types:
  # optional overrides keyed by deviceType
```

- **Decode:** `raw → typed value` when the entry is known; otherwise emit the
  event with `value=None, decoded=False` and the raw bytes intact.
- **Encode:** the inverse, used by `SetProperty`. Unknown or read-only property
  → error surfaced to the caller (not a silent drop).
- Seeded from the existing `PROPERTY_NAMES`; `type`/`scale`/`unit` fields are
  filled in as RE confirms encodings. This file is the living "handlers"
  artifact — extending device support is a data edit, not an engine change.

### `DeviceStore` interface

```
load_all() -> list[DeviceRecord]
save(record: DeviceRecord) -> None
delete(mac: bytes) -> None
```

`DeviceRecord = {mac, device_type, primary_key, fallback_key, kdf_context,
transport_key, adopted, tx_seq_hi, tx_seq_lo, ul_counter_offset, last_seen}`.

Generalizes today's single-file `_persist_adopt_keys` / `load_adopt_keys` into a
multi-device registry. The core calls the interface only; the runtime supplies
the bundled JSON-file implementation; tests use an in-memory implementation.

## Migration of `gateway.py` and the RE tooling

- Extract the session machinery from `gateway.py` into `DeviceSession` with
  behavior preserved.
- `gateway.py` becomes a thin runtime over `BridgeCore` configured with a single
  device (or `--reconnect` loading one `DeviceRecord`).
- The `sweep` / probe / fuzz logic is re-expressed as an **event observer +
  action injector**: it `subscribe()`s to events and `submit()`s
  `RequestProperty` / `Ping` / `SetPropertyRaw` actions, instead of reaching into
  private session internals. All existing RE flows keep working through the
  public API.
- The existing pytest suite (`test_crypto`, `test_decoder`, `test_gateway`,
  `test_hal`) is the regression net; behavior must stay green through the
  refactor.

## Testing strategy

All tests drive the pure engine with injected time — no Pi required.

- **Event decode:** feed captured frames from `tests/fixtures/captured_frames.py`
  into `BridgeCore.feed()`; assert the emitted `PropertyEvent` /
  `DeviceInfoEvent` fields.
- **Profile round-trips:** encode/decode each known property type; assert
  unknown ids degrade to `decoded=False` with raw preserved.
- **Multi-device routing:** two MACs interleaved; assert no cross-talk and
  correct per-device session state.
- **Store round-trip:** save → `load_all` → resume a session from a record.
- **Pairing sequence:** replay captured adopt frames through `feed()`/`tick()`
  and assert the state transitions and the persisted `DeviceRecord`.
- **Regression:** the existing suite continues to pass after the extraction.

## Success criteria

1. `BridgeCore` decodes captured real-sensor frames into typed events with
   correct decoded values for every property whose encoding is known.
2. A `SetProperty` action produces a byte-correct DL frame (validated against a
   captured example where one exists).
3. Two sensors are managed concurrently with independent sessions and no
   cross-talk.
4. `gateway.py` and the RE sweep tooling run entirely through the public
   `BridgeCore` API, and the existing pytest suite stays green.
5. Adding a new device type / property is a `superlink.yaml` edit with no engine
   code change.
