# SuperLink Protocol/Bridge Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure, multi-device SuperLink protocol/bridge core that turns decrypted frames into typed events and typed actions into outgoing frames, independent of the radio and of any northbound protocol.

**Architecture:** A new `superlink/bridge/` subpackage. `BridgeCore` (no I/O, injected time) owns a registry of `DeviceSession` objects keyed by MAC, routes received frames, drives discovery-based pairing, decodes application messages into events via a data-driven `ProfileRegistry`, and encodes actions into frames. `gateway.py` becomes a thin runtime over `BridgeCore`; the RE sweep becomes an event observer + action injector.

**Tech Stack:** Python 3.11+, `pysodium` (crypto), `PyYAML` (profiles), `pytest`. Managed with `uv`.

## Global Constraints

- Python tooling is **`uv` only** (`uv venv`, `uv pip install`, `uv run`); never raw `pip`/`python -m venv`.
- Package lives under `tools/sx1302/superlink/`; tests import as `from superlink.bridge import ...` (conftest.py already adds `tools/sx1302` to `sys.path`).
- The core is **pure**: no socket/file/serial I/O, no threads, no wall-clock reads. Time is passed in as `now: float` (seconds, monotonic domain).
- **No wire-protocol changes.** The session state machine's byte-level behavior must stay identical to today's `gateway.py`; the existing pytest suite is the regression gate.
- Multi-byte application-layer integer values are **big-endian** (matches `appmsg.py`'s device-info convention). This is the documented default; per-property overrides live in the profile YAML.
- Run tests with `uv run pytest` from repo root. Commit after every task with a `feat:`/`refactor:`/`test:` message.

---

### Task 1: Event & Action dataclasses

**Files:**
- Create: `tools/sx1302/superlink/bridge/__init__.py`
- Create: `tools/sx1302/superlink/bridge/events.py`
- Test: `tests/test_bridge_events.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - Events (frozen dataclasses, all carry `mac: bytes`): `DeviceDiscovered(mac, channel: int, first_seen: float)`, `PropertyEvent(mac, property_id: int, name: str, channel: int, raw: bytes, value, unit: str | None, decoded: bool)`, `DeviceInfoEvent(mac, device_type: int, fw_version: tuple[int,int,int], hw_revision: int, anon_id: bytes, supported_message_ids: list[int], supported_properties: list[dict])`, `DeviceStateEvent(mac, state: str)`, `RawMessageEvent(mac, message_id: int, body: bytes)`. Common base class `Event`.
  - Actions (frozen dataclasses, all carry `mac: bytes` except `AdoptDevice` which also does): `AdoptDevice(mac)`, `SetProperty(mac, name_or_id, value)`, `SetPropertyRaw(mac, property_id: int, channel: int, raw: bytes)`, `RequestProperty(mac, ids: list[int])`, `RequestDeviceInfo(mac)`, `Locate(mac)`, `Reboot(mac)`, `FactoryReset(mac)`, `Ping(mac, data: bytes = b"")`. Common base class `Action`.
  - `DEVICE_STATES = ("discovered", "adopting", "adopted", "active", "lost")`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_events.py
from superlink.bridge.events import (
    Event, Action, DeviceDiscovered, PropertyEvent, DeviceStateEvent,
    SetProperty, AdoptDevice, Ping, DEVICE_STATES,
)

MAC = bytes.fromhex("9041B22E9A53")


def test_property_event_fields_and_immutability():
    ev = PropertyEvent(mac=MAC, property_id=7, name="TEMPERATURE", channel=0,
                       raw=b"\x00\xd7", value=21.5, unit="°C", decoded=True)
    assert isinstance(ev, Event)
    assert ev.property_id == 7 and ev.value == 21.5 and ev.decoded is True
    import dataclasses, pytest
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.value = 0


def test_actions_are_actions_and_defaults():
    assert isinstance(SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=True), Action)
    assert Ping(mac=MAC).data == b""
    assert AdoptDevice(mac=MAC).mac == MAC


def test_device_state_values():
    assert DeviceStateEvent(mac=MAC, state="adopted").state in DEVICE_STATES
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_events.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge'`

- [ ] **Step 3: Write minimal implementation**

```python
# tools/sx1302/superlink/bridge/__init__.py
"""SuperLink protocol/bridge core (sub-project A)."""
```

```python
# tools/sx1302/superlink/bridge/events.py
"""Typed events (core -> consumer) and actions (consumer -> core)."""
from __future__ import annotations
from dataclasses import dataclass, field

DEVICE_STATES = ("discovered", "adopting", "adopted", "active", "lost")


class Event:
    """Base class for all core-emitted events."""


class Action:
    """Base class for all consumer-submitted actions."""


@dataclass(frozen=True)
class DeviceDiscovered(Event):
    mac: bytes
    channel: int
    first_seen: float


@dataclass(frozen=True)
class PropertyEvent(Event):
    mac: bytes
    property_id: int
    name: str
    channel: int
    raw: bytes
    value: object | None
    unit: str | None
    decoded: bool


@dataclass(frozen=True)
class DeviceInfoEvent(Event):
    mac: bytes
    device_type: int
    fw_version: tuple[int, int, int]
    hw_revision: int
    anon_id: bytes
    supported_message_ids: list[int]
    supported_properties: list[dict]


@dataclass(frozen=True)
class DeviceStateEvent(Event):
    mac: bytes
    state: str


@dataclass(frozen=True)
class RawMessageEvent(Event):
    mac: bytes
    message_id: int
    body: bytes


@dataclass(frozen=True)
class AdoptDevice(Action):
    mac: bytes


@dataclass(frozen=True)
class SetProperty(Action):
    mac: bytes
    name_or_id: str | int
    value: object


@dataclass(frozen=True)
class SetPropertyRaw(Action):
    mac: bytes
    property_id: int
    channel: int
    raw: bytes


@dataclass(frozen=True)
class RequestProperty(Action):
    mac: bytes
    ids: list[int]


@dataclass(frozen=True)
class RequestDeviceInfo(Action):
    mac: bytes


@dataclass(frozen=True)
class Locate(Action):
    mac: bytes


@dataclass(frozen=True)
class Reboot(Action):
    mac: bytes


@dataclass(frozen=True)
class FactoryReset(Action):
    mac: bytes


@dataclass(frozen=True)
class Ping(Action):
    mac: bytes
    data: bytes = b""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_bridge_events.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/__init__.py tools/sx1302/superlink/bridge/events.py tests/test_bridge_events.py
git commit -m "feat: bridge core event and action dataclasses"
```

---

### Task 2: Profile registry (data-driven property decode/encode)

**Files:**
- Create: `tools/sx1302/superlink/bridge/profiles/superlink.yaml`
- Create: `tools/sx1302/superlink/bridge/profiles.py`
- Test: `tests/test_bridge_profiles.py`

**Interfaces:**
- Consumes: nothing (loads its own YAML).
- Produces: `ProfileRegistry` with:
  - `ProfileRegistry.load(path: str | None = None) -> ProfileRegistry` (default path = bundled `profiles/superlink.yaml`).
  - `resolve_id(self, name_or_id: str | int) -> int` — name→id or passthrough id; raises `KeyError` for an unknown name.
  - `name(self, property_id: int) -> str` — `UNKNOWN_<n>` for undefined ids.
  - `decode(self, property_id: int, raw: bytes, device_type: int | None = None) -> tuple[object | None, str | None, bool]` — returns `(value, unit, decoded)`; `(None, None, False)` when no profile.
  - `encode(self, name_or_id: str | int, value, device_type: int | None = None) -> tuple[int, bytes]` — raises `KeyError` (unknown), `PermissionError` (read-only), or `ValueError` (bad value/type).

Supported `type` values: `u8`, `u16`, `u32`, `s16` (big-endian), `bool` (1 byte, `!=0`). Optional `scale: float` (decoded value = `int * scale`; encoded int = `round(value / scale)`). Optional `unit: str`. Optional `access: r|rw` (default `r`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_profiles.py
import pytest
from superlink.bridge.profiles import ProfileRegistry


@pytest.fixture
def reg():
    return ProfileRegistry.load()


def test_decode_known_scaled(reg):
    # TEMPERATURE (id 7): s16 big-endian, scale 0.1
    value, unit, decoded = reg.decode(7, (215).to_bytes(2, "big"))
    assert decoded is True and value == pytest.approx(21.5) and unit == "°C"


def test_decode_bool(reg):
    value, unit, decoded = reg.decode(4, b"\x01")  # LEAK_DETECTED
    assert decoded is True and value is True


def test_decode_unknown_passes_through(reg):
    value, unit, decoded = reg.decode(200, b"\xde\xad")
    assert decoded is False and value is None and unit is None


def test_encode_roundtrip(reg):
    pid, raw = reg.encode("LED_ENABLED", True)  # id 14, bool, rw
    assert pid == 14 and raw == b"\x01"


def test_encode_readonly_raises(reg):
    with pytest.raises(PermissionError):
        reg.encode("BATTERY", 50)  # id 3, read-only


def test_resolve_and_name(reg):
    assert reg.resolve_id("TEMPERATURE") == 7
    assert reg.resolve_id(7) == 7
    assert reg.name(999) == "UNKNOWN_999"
    with pytest.raises(KeyError):
        reg.resolve_id("NOPE")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_profiles.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.profiles'`

- [ ] **Step 3: Ensure PyYAML is installed**

Run: `uv pip install pyyaml`
Expected: installs or reports already satisfied.

- [ ] **Step 4: Write the YAML data file**

Seed every id from `appmsg.PROPERTY_NAMES`; fill `type`/`unit`/`scale`/`access` only where confidently known, leave the rest name-only (they still decode raw with `decoded=False` because they lack a `type`).

```yaml
# tools/sx1302/superlink/bridge/profiles/superlink.yaml
# Property decode/encode profiles. name-only entries decode as raw
# (decoded=false) until their wire type is confirmed. Multi-byte ints are
# big-endian. See docs/protocol/superlink_application_layer.md.
properties:
  1:  { name: UPTIME,           type: u32, unit: s }
  2:  { name: SIGNAL,           type: s16 }
  3:  { name: BATTERY,          type: u8,  unit: "%", access: r }
  4:  { name: LEAK_DETECTED,    type: bool }
  5:  { name: LEAK_AUX_CONNECTED, type: bool }
  6:  { name: LEAK_CONFIG }
  7:  { name: TEMPERATURE,      type: s16, scale: 0.1, unit: "°C" }
  8:  { name: TEMPERATURE_CONFIG }
  9:  { name: HUMIDITY,         type: u16, scale: 0.1, unit: "%" }
  10: { name: HUMIDITY_CONFIG }
  11: { name: AMBIENT_LIGHT,    type: u16, unit: lux }
  12: { name: AMBIENT_LIGHT_CONFIG }
  13: { name: REPORT_INTERVAL,  type: u16, unit: s, access: rw }
  14: { name: LED_ENABLED,      type: bool, access: rw }
  15: { name: ENTRY_DETECTED,   type: bool }
  16: { name: ENTRY_CONFIG }
  17: { name: FIRMWARE_VERSION }
  19: { name: BUTTON_PRESSED,   type: bool }
  20: { name: TAMPER_DETECTED,  type: bool }
  21: { name: TAMPER_CONFIG }
  22: { name: TAMPER_CLEAR }
  23: { name: MOTION_DETECTED,  type: bool }
  24: { name: MOTION_CONFIG }
  25: { name: ACCELERATION }
  26: { name: ACCELERATION_CONFIG }
  27: { name: SMOKE_STATUS,     type: u8 }
  28: { name: SMOKE_ALARM_SILENCE }
  29: { name: SMOKE_TROUBLE_SILENCE }
  30: { name: SMOKE_TEST }
  31: { name: SMOKE_REMOTE_STATUS }
  32: { name: LED_FEEDBACK_CONFIG }
  33: { name: GLASS_BREAK_DETECTED, type: bool }
  34: { name: GLASS_BREAK_CLEAR }
  35: { name: GLASS_BREAK_CONFIG }
  36: { name: ALARM_SOUND_CONTROL,  access: rw }
  37: { name: ALARM_SOUND_CONFIG }
  38: { name: ALARM_LIGHT_CONTROL,  access: rw }
  39: { name: ALARM_LIGHT_CONFIG }
  40: { name: BUTTON_LONG_PRESSED,   type: bool }
  41: { name: BUTTON_DOUBLE_PRESSED, type: bool }
  42: { name: BUTTON_CONFIG }
device_types: {}   # optional per-deviceType overrides, same entry shape
```

- [ ] **Step 5: Write the implementation**

```python
# tools/sx1302/superlink/bridge/profiles.py
"""Data-driven property decode/encode profiles."""
from __future__ import annotations
import os
import yaml

_INT_TYPES = {"u8": (1, False), "u16": (2, False),
              "u32": (4, False), "s16": (2, True)}
_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "profiles", "superlink.yaml")


class ProfileRegistry:
    def __init__(self, properties: dict, device_types: dict):
        self._props = {int(k): v for k, v in properties.items()}
        self._by_name = {v["name"]: int(k) for k, v in self._props.items()}
        self._device_types = device_types or {}

    @classmethod
    def load(cls, path: str | None = None) -> "ProfileRegistry":
        with open(path or _DEFAULT_PATH) as f:
            doc = yaml.safe_load(f)
        return cls(doc.get("properties", {}), doc.get("device_types", {}))

    def _entry(self, property_id: int, device_type: int | None):
        if device_type is not None:
            override = self._device_types.get(device_type, {}).get(property_id)
            if override:
                return override
        return self._props.get(property_id)

    def resolve_id(self, name_or_id: str | int) -> int:
        if isinstance(name_or_id, int):
            return name_or_id
        return self._by_name[name_or_id]  # KeyError if unknown

    def name(self, property_id: int) -> str:
        entry = self._props.get(property_id)
        return entry["name"] if entry else f"UNKNOWN_{property_id}"

    def decode(self, property_id: int, raw: bytes,
               device_type: int | None = None):
        entry = self._entry(property_id, device_type)
        if not entry or "type" not in entry:
            return None, None, False
        t = entry["type"]
        unit = entry.get("unit")
        if t == "bool":
            return (any(raw), unit, True)
        size, signed = _INT_TYPES[t]
        n = int.from_bytes(raw[:size], "big", signed=signed)
        if "scale" in entry:
            return (n * entry["scale"], unit, True)
        return (n, unit, True)

    def encode(self, name_or_id: str | int, value,
               device_type: int | None = None) -> tuple[int, bytes]:
        pid = self.resolve_id(name_or_id)
        entry = self._entry(pid, device_type)
        if not entry or "type" not in entry:
            raise KeyError(f"no encodable profile for property {name_or_id}")
        if entry.get("access", "r") != "rw":
            raise PermissionError(f"property {entry['name']} is read-only")
        t = entry["type"]
        if t == "bool":
            return pid, b"\x01" if value else b"\x00"
        size, signed = _INT_TYPES[t]
        n = round(value / entry["scale"]) if "scale" in entry else int(value)
        try:
            return pid, n.to_bytes(size, "big", signed=signed)
        except OverflowError as exc:
            raise ValueError(f"{value} out of range for {t}") from exc
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_profiles.py -v`
Expected: PASS (6 passed)

- [ ] **Step 7: Commit**

```bash
git add tools/sx1302/superlink/bridge/profiles.py tools/sx1302/superlink/bridge/profiles/superlink.yaml tests/test_bridge_profiles.py
git commit -m "feat: data-driven property profile registry"
```

---

### Task 3: Device store (registry persistence interface)

**Files:**
- Create: `tools/sx1302/superlink/bridge/store.py`
- Test: `tests/test_bridge_store.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `DeviceRecord` dataclass: `mac: bytes`, `device_type: int | None = None`, `primary_key: bytes | None = None`, `fallback_key: bytes | None = None`, `kdf_context: bytes | None = None`, `transport_key: bytes | None = None`, `adopted: bool = False`, `tx_seq_hi: int = 0`, `tx_seq_lo: int = 0`, `ul_counter_offset: int = 5`, `last_seen: float = 0.0`.
  - `DeviceStore` abstract base: `load_all() -> list[DeviceRecord]`, `save(record: DeviceRecord) -> None`, `delete(mac: bytes) -> None`.
  - `InMemoryDeviceStore(DeviceStore)` and `JsonDeviceStore(DeviceStore)` (`__init__(self, path: str)`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_store.py
from superlink.bridge.store import DeviceRecord, InMemoryDeviceStore, JsonDeviceStore

MAC = bytes.fromhex("9041B22E9A53")


def _rec():
    return DeviceRecord(mac=MAC, device_type=0x0100,
                        primary_key=b"\x11" * 32, fallback_key=b"\x22" * 32,
                        adopted=True, tx_seq_hi=5, ul_counter_offset=5,
                        last_seen=123.0)


def test_inmemory_roundtrip():
    s = InMemoryDeviceStore()
    s.save(_rec())
    got = s.load_all()
    assert len(got) == 1 and got[0].mac == MAC and got[0].primary_key == b"\x11" * 32


def test_inmemory_save_is_upsert_and_delete():
    s = InMemoryDeviceStore()
    s.save(_rec())
    s.save(DeviceRecord(mac=MAC, device_type=0x0200))  # overwrite
    assert s.load_all()[0].device_type == 0x0200
    s.delete(MAC)
    assert s.load_all() == []


def test_json_roundtrip(tmp_path):
    path = str(tmp_path / "devices.json")
    s = JsonDeviceStore(path)
    s.save(_rec())
    reloaded = JsonDeviceStore(path).load_all()
    assert len(reloaded) == 1
    r = reloaded[0]
    assert r.mac == MAC and r.fallback_key == b"\x22" * 32 and r.adopted is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.store'`

- [ ] **Step 3: Write the implementation**

```python
# tools/sx1302/superlink/bridge/store.py
"""Device registry persistence: interface + in-memory and JSON impls."""
from __future__ import annotations
import abc
import json
import os
from dataclasses import dataclass, asdict, fields


@dataclass
class DeviceRecord:
    mac: bytes
    device_type: int | None = None
    primary_key: bytes | None = None
    fallback_key: bytes | None = None
    kdf_context: bytes | None = None
    transport_key: bytes | None = None
    adopted: bool = False
    tx_seq_hi: int = 0
    tx_seq_lo: int = 0
    ul_counter_offset: int = 5
    last_seen: float = 0.0


_BYTES_FIELDS = ("mac", "primary_key", "fallback_key", "kdf_context", "transport_key")


def _to_json(rec: DeviceRecord) -> dict:
    d = asdict(rec)
    for k in _BYTES_FIELDS:
        d[k] = d[k].hex() if d[k] is not None else None
    return d


def _from_json(d: dict) -> DeviceRecord:
    allowed = {f.name for f in fields(DeviceRecord)}
    d = {k: v for k, v in d.items() if k in allowed}
    for k in _BYTES_FIELDS:
        if d.get(k) is not None:
            d[k] = bytes.fromhex(d[k])
    return DeviceRecord(**d)


class DeviceStore(abc.ABC):
    @abc.abstractmethod
    def load_all(self) -> list[DeviceRecord]: ...
    @abc.abstractmethod
    def save(self, record: DeviceRecord) -> None: ...
    @abc.abstractmethod
    def delete(self, mac: bytes) -> None: ...


class InMemoryDeviceStore(DeviceStore):
    def __init__(self):
        self._records: dict[bytes, DeviceRecord] = {}

    def load_all(self) -> list[DeviceRecord]:
        return list(self._records.values())

    def save(self, record: DeviceRecord) -> None:
        self._records[record.mac] = record

    def delete(self, mac: bytes) -> None:
        self._records.pop(mac, None)


class JsonDeviceStore(DeviceStore):
    def __init__(self, path: str):
        self.path = path

    def _read(self) -> dict[str, dict]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path) as f:
            return json.load(f)

    def _write(self, data: dict[str, dict]) -> None:
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)

    def load_all(self) -> list[DeviceRecord]:
        return [_from_json(v) for v in self._read().values()]

    def save(self, record: DeviceRecord) -> None:
        data = self._read()
        data[record.mac.hex()] = _to_json(record)
        self._write(data)

    def delete(self, mac: bytes) -> None:
        data = self._read()
        data.pop(mac.hex(), None)
        self._write(data)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_store.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/store.py tests/test_bridge_store.py
git commit -m "feat: device store interface with in-memory and json impls"
```

---

### Task 4: Application-layer action encoders

**Files:**
- Modify: `tools/sx1302/superlink/appmsg.py` (append encoders after the existing `encode_property_request`)
- Test: `tests/test_bridge_appmsg_encoders.py`

**Interfaces:**
- Consumes: existing `appmsg.MessageId`.
- Produces (added to `appmsg`):
  - `encode_property_set(entries: list[tuple[int, int, bytes]], tag: int = 0) -> bytes` — `entries` are `(property_id, channel, raw_value)`; body = `[14, tag] + for each: [id, channel] + raw`.
  - `encode_reboot(tag: int = 0) -> bytes` → `[6, tag]`
  - `encode_factory_reset(tag: int = 0) -> bytes` → `[7, tag]`
  - `encode_locate(tag: int = 0) -> bytes` → `[8, tag]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_appmsg_encoders.py
from superlink import appmsg


def test_encode_property_set():
    body = appmsg.encode_property_set([(14, 0, b"\x01")], tag=0x2a)
    assert body == bytes([14, 0x2a, 14, 0, 0x01])


def test_encode_property_set_multi():
    body = appmsg.encode_property_set([(13, 0, b"\x00\x3c"), (14, 0, b"\x00")])
    assert body == bytes([14, 0, 13, 0, 0x00, 0x3c, 14, 0, 0x00])


def test_encode_simple_commands():
    assert appmsg.encode_reboot(1) == bytes([6, 1])
    assert appmsg.encode_factory_reset(2) == bytes([7, 2])
    assert appmsg.encode_locate(3) == bytes([8, 3])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_appmsg_encoders.py -v`
Expected: FAIL with `AttributeError: module 'superlink.appmsg' has no attribute 'encode_property_set'`

- [ ] **Step 3: Write the implementation**

Append to `tools/sx1302/superlink/appmsg.py`:

```python
def encode_property_set(entries, tag: int = 0) -> bytes:
    """PROPERTY_SET body: [14, tag] + for each (id, channel, raw): id, channel, raw."""
    out = bytearray([MessageId.PROPERTY_SET, tag & 0xFF])
    for property_id, channel, raw in entries:
        out += bytes([property_id & 0xFF, channel & 0xFF])
        out += bytes(raw)
    return bytes(out)


def encode_reboot(tag: int = 0) -> bytes:
    """REBOOT body: [6, tag]. Header only."""
    return bytes([MessageId.REBOOT, tag & 0xFF])


def encode_factory_reset(tag: int = 0) -> bytes:
    """FACTORY_RESET body: [7, tag]. Header only."""
    return bytes([MessageId.FACTORY_RESET, tag & 0xFF])


def encode_locate(tag: int = 0) -> bytes:
    """LOCATE body: [8, tag]. Header only."""
    return bytes([MessageId.LOCATE, tag & 0xFF])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_appmsg_encoders.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/appmsg.py tests/test_bridge_appmsg_encoders.py
git commit -m "feat: application-layer action encoders (property_set, reboot, factory_reset, locate)"
```

---

### Task 5: Message→event mapping and action→body encoding

**Files:**
- Create: `tools/sx1302/superlink/bridge/mapping.py`
- Test: `tests/test_bridge_mapping.py`

**Interfaces:**
- Consumes: `appmsg.decode_message`, `appmsg.MessageId`, `ProfileRegistry`, event/action dataclasses.
- Produces:
  - `events_from_app_message(mac: bytes, body: bytes, profiles: ProfileRegistry, sizes: dict | None = None, device_type: int | None = None) -> list[Event]` — decodes one app message body into zero or more events (`PropertyEvent` per property in a report, `DeviceInfoEvent`, else `RawMessageEvent`).
  - `action_to_body(action: Action, profiles: ProfileRegistry, tag: int = 0, device_type: int | None = None) -> bytes` — encodes an action into an app-message body. Raises `TypeError` for an action with no wire encoding (e.g. `AdoptDevice`, handled by the session, not here).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_mapping.py
import pytest
from superlink import appmsg
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.mapping import events_from_app_message, action_to_body
from superlink.bridge.events import (
    PropertyEvent, DeviceInfoEvent, RawMessageEvent,
    SetProperty, RequestProperty, Reboot, Ping,
)

MAC = bytes.fromhex("9041B22E9A53")


@pytest.fixture
def reg():
    return ProfileRegistry.load()


def test_property_report_maps_to_events(reg):
    # PROPERTY_REPORT (id 12): LEAK_DETECTED(4) ch0 = 01, BATTERY(3) ch0 = 50
    body = bytes([12, 0]) + bytes([4, 0, 0x01]) + bytes([3, 0, 50])
    sizes = {4: 1, 3: 1}
    evs = events_from_app_message(MAC, body, reg, sizes=sizes)
    assert [type(e) for e in evs] == [PropertyEvent, PropertyEvent]
    assert evs[0].name == "LEAK_DETECTED" and evs[0].value is True
    assert evs[1].name == "BATTERY" and evs[1].value == 50 and evs[1].unit == "%"


def test_unknown_message_is_raw(reg):
    body = bytes([200, 7, 0xaa, 0xbb])
    evs = events_from_app_message(MAC, body, reg)
    assert len(evs) == 1 and isinstance(evs[0], RawMessageEvent)
    assert evs[0].message_id == 200 and evs[0].body == b"\xaa\xbb"


def test_action_to_body_set_property(reg):
    body = action_to_body(SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=True), reg, tag=9)
    assert body == bytes([14, 9, 14, 0, 0x01])


def test_action_to_body_requests_and_commands(reg):
    assert action_to_body(RequestProperty(mac=MAC, ids=[3, 7]), reg, tag=1) == bytes([11, 1, 3, 7])
    assert action_to_body(Reboot(mac=MAC), reg, tag=2) == bytes([6, 2])
    assert action_to_body(Ping(mac=MAC, data=b"\xff"), reg, tag=3) == bytes([4, 3, 0xff])


def test_adopt_has_no_body(reg):
    from superlink.bridge.events import AdoptDevice
    with pytest.raises(TypeError):
        action_to_body(AdoptDevice(mac=MAC), reg)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_mapping.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.mapping'`

- [ ] **Step 3: Write the implementation**

```python
# tools/sx1302/superlink/bridge/mapping.py
"""Pure translation between application-layer messages and typed events/actions."""
from __future__ import annotations
from .. import appmsg
from .events import (
    Event, Action, PropertyEvent, DeviceInfoEvent, RawMessageEvent,
    SetProperty, SetPropertyRaw, RequestProperty, RequestDeviceInfo,
    Locate, Reboot, FactoryReset, Ping,
)
from .profiles import ProfileRegistry


def events_from_app_message(mac, body, profiles: ProfileRegistry,
                            sizes=None, device_type=None) -> list[Event]:
    if len(body) < 2:
        return []
    msg = appmsg.decode_message(body, sizes=sizes)
    msg_id = msg["messageId"]

    if msg_id == appmsg.MessageId.DEVICE_INFO_REPORT:
        return [DeviceInfoEvent(
            mac=mac, device_type=msg["deviceType"], fw_version=msg["fwVersion"],
            hw_revision=msg["hardwareRevision"], anon_id=msg["anonymousDeviceId"],
            supported_message_ids=msg["supportedMessageIds"],
            supported_properties=msg["supportedProperties"])]

    if msg_id in (appmsg.MessageId.PROPERTY_REPORT, appmsg.MessageId.PROPERTY_SET):
        out = []
        for p in msg["properties"]:
            pid, raw = p["propertyId"], p["value"]
            value, unit, decoded = profiles.decode(pid, raw, device_type)
            out.append(PropertyEvent(
                mac=mac, property_id=pid, name=profiles.name(pid),
                channel=p["channel"], raw=raw, value=value, unit=unit,
                decoded=decoded))
        return out

    return [RawMessageEvent(mac=mac, message_id=msg_id, body=bytes(body[2:]))]


def action_to_body(action: Action, profiles: ProfileRegistry,
                   tag: int = 0, device_type=None) -> bytes:
    if isinstance(action, SetProperty):
        pid, raw = profiles.encode(action.name_or_id, action.value, device_type)
        return appmsg.encode_property_set([(pid, 0, raw)], tag=tag)
    if isinstance(action, SetPropertyRaw):
        return appmsg.encode_property_set([(action.property_id, action.channel, action.raw)], tag=tag)
    if isinstance(action, RequestProperty):
        return appmsg.encode_property_request(action.ids, tag=tag)
    if isinstance(action, RequestDeviceInfo):
        return appmsg.encode_device_info_request(tag=tag)
    if isinstance(action, Ping):
        return appmsg.encode_ping_request(tag=tag, data=action.data)
    if isinstance(action, Locate):
        return appmsg.encode_locate(tag=tag)
    if isinstance(action, Reboot):
        return appmsg.encode_reboot(tag=tag)
    if isinstance(action, FactoryReset):
        return appmsg.encode_factory_reset(tag=tag)
    raise TypeError(f"{type(action).__name__} has no application-layer body")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_mapping.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/mapping.py tests/test_bridge_mapping.py
git commit -m "feat: message-to-event and action-to-body mapping"
```

---

### Task 6: BridgeCore orchestration (registry, routing, discovery)

**Files:**
- Create: `tools/sx1302/superlink/bridge/core.py`
- Test: `tests/test_bridge_core.py`

**Interfaces:**
- Consumes: `parse_frame` (`superlink.decoder`), `DeviceStore`/`DeviceRecord`, `ProfileRegistry`, `events_from_app_message`, `action_to_body`, all event/action types.
- Produces:
  - `SessionProtocol` (typing.Protocol): a device session must expose `mac: bytes`, `feed(frame, channel, now) -> tuple[list[OutgoingFrame], list[Event]]`, `tick(now) -> tuple[list[OutgoingFrame], list[Event]]`, `queue_body(body: bytes) -> None`, and `state: str`.
  - `OutgoingFrame` dataclass: `data: bytes`, `freq_hz: int`, `channel: int`.
  - `BridgeCore(store: DeviceStore, profiles: ProfileRegistry, session_factory, auto_adopt: bool = False)`. `session_factory(record: DeviceRecord) -> SessionProtocol` builds a session for an (adopting or restored) device.
  - Methods: `subscribe(cb)`, `feed(raw, channel, now) -> list[OutgoingFrame]`, `tick(now) -> list[OutgoingFrame]`, `submit(action: Action)`.

Routing rules for `feed`: parse frame → if MAC has a session, delegate to it and translate the app-message body it returns into events; else if MAC is a known-but-unadopted discovered device, ignore (already announced); else emit `DeviceDiscovered` + `DeviceStateEvent("discovered")` and remember it. `AdoptDevice` (or `auto_adopt`) promotes a discovered MAC by calling `session_factory` and emitting `DeviceStateEvent("adopting")`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_core.py
from superlink.bridge.core import BridgeCore, OutgoingFrame
from superlink.bridge.store import InMemoryDeviceStore, DeviceRecord
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.events import (
    DeviceDiscovered, DeviceStateEvent, PropertyEvent, AdoptDevice, Event,
)

MAC = bytes.fromhex("9041B22E9A53")
# 0x54 UL data frame from an unknown MAC (header + >=4 encrypted bytes)
UNKNOWN_FRAME = bytes.fromhex("E054" + MAC.hex() + "5B11" + "9CFFC24C" + "8A")


class FakeSession:
    """Test double implementing SessionProtocol; emits one PropertyEvent per feed."""
    def __init__(self, record):
        self.mac = record.mac
        self.state = "adopted"
        self.queued = []
    def feed(self, frame, channel, now):
        ev = PropertyEvent(mac=self.mac, property_id=3, name="BATTERY",
                           channel=0, raw=b"\x64", value=100, unit="%", decoded=True)
        return [], [ev]
    def tick(self, now):
        return [], []
    def queue_body(self, body):
        self.queued.append(body)


def _core(auto_adopt=False):
    return BridgeCore(InMemoryDeviceStore(), ProfileRegistry.load(),
                      session_factory=FakeSession, auto_adopt=auto_adopt)


def test_unknown_device_is_discovered_not_adopted():
    core = _core()
    seen = []
    core.subscribe(seen.append)
    core.feed(UNKNOWN_FRAME, channel=1, now=1.0)
    kinds = [type(e) for e in seen]
    assert DeviceDiscovered in kinds
    assert not any(isinstance(e, PropertyEvent) for e in seen)
    # A second frame from the same undiscovered->discovered MAC does not re-announce
    seen.clear()
    core.feed(UNKNOWN_FRAME, channel=1, now=2.0)
    assert not any(isinstance(e, DeviceDiscovered) for e in seen)


def test_adopt_action_promotes_and_then_events_flow():
    core = _core()
    seen = []
    core.subscribe(seen.append)
    core.feed(UNKNOWN_FRAME, channel=1, now=1.0)      # discovered
    core.submit(AdoptDevice(mac=MAC))                  # approve
    seen.clear()
    core.feed(UNKNOWN_FRAME, channel=1, now=3.0)      # now routed to session
    assert any(isinstance(e, PropertyEvent) and e.value == 100 for e in seen)


def test_auto_adopt_skips_approval():
    core = _core(auto_adopt=True)
    seen = []
    core.subscribe(seen.append)
    core.feed(UNKNOWN_FRAME, channel=1, now=1.0)
    # session created immediately; its event surfaces without an explicit adopt
    assert any(isinstance(e, PropertyEvent) for e in seen)


def test_submit_setproperty_queues_body_on_session():
    from superlink.bridge.events import SetProperty
    core = _core(auto_adopt=True)
    core.feed(UNKNOWN_FRAME, channel=1, now=1.0)
    core.submit(SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=True))
    session = core._sessions[MAC]
    assert session.queued and session.queued[0] == bytes([14, 0, 14, 0, 0x01])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_core.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.core'`

- [ ] **Step 3: Write the implementation**

```python
# tools/sx1302/superlink/bridge/core.py
"""BridgeCore: pure multi-device orchestrator over DeviceSessions."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Protocol

from ..decoder import parse_frame
from .events import (
    Event, Action, AdoptDevice, DeviceDiscovered, DeviceStateEvent,
)
from .mapping import action_to_body
from .profiles import ProfileRegistry
from .store import DeviceStore, DeviceRecord


@dataclass
class OutgoingFrame:
    data: bytes
    freq_hz: int
    channel: int


class SessionProtocol(Protocol):
    mac: bytes
    state: str
    def feed(self, frame, channel: int, now: float): ...
    def tick(self, now: float): ...
    def queue_body(self, body: bytes) -> None: ...


class BridgeCore:
    def __init__(self, store: DeviceStore, profiles: ProfileRegistry,
                 session_factory: Callable[[DeviceRecord], SessionProtocol],
                 auto_adopt: bool = False):
        self.store = store
        self.profiles = profiles
        self._factory = session_factory
        self.auto_adopt = auto_adopt
        self._sessions: dict[bytes, SessionProtocol] = {}
        self._discovered: dict[bytes, float] = {}
        self._subscribers: list[Callable[[Event], None]] = []
        for record in store.load_all():
            self._sessions[record.mac] = session_factory(record)

    def subscribe(self, cb: Callable[[Event], None]) -> None:
        self._subscribers.append(cb)

    def _emit(self, events) -> None:
        for ev in events:
            for cb in self._subscribers:
                cb(ev)

    def feed(self, raw: bytes, channel: int, now: float) -> list[OutgoingFrame]:
        frame = parse_frame(raw)
        if frame is None:
            return []
        mac = frame.mac
        session = self._sessions.get(mac)
        if session is not None:
            frames, events = session.feed(frame, channel, now)
            self._emit(events)
            return list(frames)
        if mac in self._discovered:
            return []  # already announced; awaiting AdoptDevice / auto_adopt
        self._discovered[mac] = now
        self._emit([DeviceDiscovered(mac=mac, channel=channel, first_seen=now),
                    DeviceStateEvent(mac=mac, state="discovered")])
        if self.auto_adopt:
            self._adopt(mac)
            session = self._sessions[mac]
            frames, events = session.feed(frame, channel, now)
            self._emit(events)
            return list(frames)
        return []

    def _adopt(self, mac: bytes) -> None:
        self._discovered.pop(mac, None)
        record = DeviceRecord(mac=mac)
        self._sessions[mac] = self._factory(record)
        self._emit([DeviceStateEvent(mac=mac, state="adopting")])

    def tick(self, now: float) -> list[OutgoingFrame]:
        out: list[OutgoingFrame] = []
        for session in self._sessions.values():
            frames, events = session.tick(now)
            out.extend(frames)
            self._emit(events)
        return out

    def submit(self, action: Action) -> None:
        if isinstance(action, AdoptDevice):
            if action.mac in self._discovered:
                self._adopt(action.mac)
            return
        session = self._sessions.get(action.mac)
        if session is None:
            return
        session.queue_body(action_to_body(action, self.profiles))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_core.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/core.py tests/test_bridge_core.py
git commit -m "feat: BridgeCore orchestration with discovery-driven pairing"
```

---

### Task 7: Extract DeviceSession from gateway.py (behavior-preserving)

**Files:**
- Create: `tools/sx1302/superlink/bridge/session.py`
- Modify: `tools/sx1302/superlink/gateway.py` (import the extracted class; keep RE hooks)
- Test: `tests/test_bridge_session.py` + existing `tests/test_gateway.py` as regression gate.

**Interfaces:**
- Consumes: `superlink.decoder`, `superlink.crypto`, `superlink.appmsg`, `superlink.adopt`, `DeviceRecord`, event types, `OutgoingFrame`.
- Produces: `DeviceSession` implementing `SessionProtocol`:
  - `DeviceSession(record: DeviceRecord, gw_mac: bytes, pairing_key: bytes, profiles: ProfileRegistry, beacon_interval: float = 240.0, network_id: int = ..., now: float = 0.0)`.
  - `feed(frame, channel, now) -> tuple[list[OutgoingFrame], list[Event]]`, `tick(now) -> tuple[list[OutgoingFrame], list[Event]]`, `queue_body(body)`, attribute `state: str`, and `to_record() -> DeviceRecord`.

This task is a **refactor, not new behavior.** Move the working state-machine methods (`_handle_active`, `_handle_beaconing`, `_build_dl_reply`, `_build_0x74_reply`, `_build_command`, `_scan_data_counter`, beacon logic, the adopt round-trip handling) out of `GatewaySession` into `DeviceSession` **unchanged in logic**. The two seams that change:
1. Instead of returning a `(frame, tx_data, tx_freq)` tuple, `feed`/`tick` return `(list[OutgoingFrame], list[Event])`. Wrap each existing `tx_data`/`freq` as one `OutgoingFrame(data, freq_hz, channel)`.
2. Instead of routing decrypted app bodies into `self.sweep` (`_ingest_app_report`), call `events_from_app_message(...)` and return the events. The `sweep` hook is removed from the session (it re-attaches in Task 9 as an observer).

Actions queued via `queue_body` are transmitted on the device's next DL window using the existing `_build_command` path (previously the `_next_probe_body` mechanism); replace the probe-specific `_next_probe_body` call site with "pop the next queued body, if any."

- [ ] **Step 1: Characterize current behavior (regression baseline)**

Run: `uv run pytest tests/test_gateway.py -v`
Expected: PASS — record the count. This is the behavior that must not change.

- [ ] **Step 2: Write the failing test for the new surface**

```python
# tests/test_bridge_session.py
from superlink.bridge.session import DeviceSession
from superlink.bridge.core import OutgoingFrame
from superlink.bridge.store import DeviceRecord
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.events import Event
from fixtures.captured_frames import (
    SENSOR_MAC, DEFAULT_PAIRING_KEY, FRAME_36B_RAW,
)

GW_MAC = bytes.fromhex("0102030405")  # 5-byte gw mac used by gateway today


def _session():
    return DeviceSession(DeviceRecord(mac=SENSOR_MAC), gw_mac=GW_MAC,
                         pairing_key=DEFAULT_PAIRING_KEY, profiles=ProfileRegistry.load())


def test_feed_returns_frames_and_events_tuple():
    from superlink.decoder import parse_frame
    s = _session()
    frame = parse_frame(FRAME_36B_RAW)   # real parsed SuperLinkFrame
    result = s.feed(frame, channel=1, now=1.0)
    assert isinstance(result, tuple) and len(result) == 2
    frames, events = result
    assert isinstance(frames, list) and isinstance(events, list)


def test_to_record_roundtrips_identity():
    s = _session()
    rec = s.to_record()
    assert rec.mac == SENSOR_MAC


def test_beacon_emitted_on_tick_when_due():
    s = _session()
    s.start(now=0.0)                    # enter BEACONING
    frames, _ = s.tick(now=1000.0)      # well past beacon_interval
    assert any(isinstance(f, OutgoingFrame) for f in frames)
```

> Note: `feed` takes a parsed `SuperLinkFrame`, so the session-level tests drive it through parsed frames; the raw-frame path is covered end-to-end in Task 8. Keep these tests minimal — the real regression gate is `tests/test_gateway.py` in Step 5.

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_session.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.session'`

- [ ] **Step 4: Perform the extraction**

1. Copy `GatewaySession` (gateway.py:50-838) into `bridge/session.py` as `DeviceSession`.
2. Delete the `sweep`, `_sweep_tag`, `_ingest_app_report`, `_next_probe_body` RE members; where `_ingest_app_report` was called, build events with `events_from_app_message(frame.mac, frame.payload, self.profiles, sizes=self._prop_sizes, device_type=self._device_type)` and collect them into the returned event list.
3. Change `handle_rx` and the `_handle_*`/beacon methods to accumulate `OutgoingFrame(data, freq_hz, channel)` and `Event` objects and return `(frames, events)` instead of the `(frame, tx_data, freq)` tuple. Rename `handle_rx` to `feed`.
4. Add `state` as a plain `str` property mirroring `self._state.value` (map the internal `State` enum to the `DEVICE_STATES` vocabulary: `BEACONING/DH/CHALLENGE/SETUP → "adopting"`, `ACTIVE → "active"`, adopted flag → `"adopted"`).
5. Add `queue_body(self, body)` appending to `self._pending_bodies: list[bytes]`, and in the DL-window builder pop from it instead of calling `_next_probe_body`.
6. Add `to_record()` returning a `DeviceRecord` populated from `sensor_mac`, derived keys, `kdf_context`, `transport_key`, `adopted`, seq counters, and `ul_counter_offset`; add a classmethod or `__init__` path that restores those fields from a passed `DeviceRecord`.
7. In `gateway.py`, replace the `GatewaySession` body with `from .bridge.session import DeviceSession` and a thin subclass/alias so the existing `gateway.py` entrypoints still construct and drive it. (Full runtime rewrite happens in Task 9; here just keep imports working and tests green.)

- [ ] **Step 5: Run the regression gate + new tests**

Run: `uv run pytest tests/test_gateway.py tests/test_bridge_session.py -v`
Expected: `tests/test_gateway.py` PASS with the **same count** as Step 1; `tests/test_bridge_session.py` PASS.

- [ ] **Step 6: Full suite**

Run: `uv run pytest tests/ -v`
Expected: all PASS (existing + Tasks 1-6).

- [ ] **Step 7: Commit**

```bash
git add tools/sx1302/superlink/bridge/session.py tools/sx1302/superlink/gateway.py tests/test_bridge_session.py
git commit -m "refactor: extract DeviceSession from gateway.py, event/frame surface"
```

---

### Task 8: End-to-end integration (raw frames → events through BridgeCore + DeviceSession)

**Files:**
- Create: `tests/test_bridge_integration.py`
- Modify: `tools/sx1302/superlink/bridge/core.py` only if a wiring gap surfaces (document any change in the commit).

**Interfaces:**
- Consumes: everything from Tasks 1-7. `session_factory` is now `DeviceSession`.

- [ ] **Step 1: Write the failing/int test**

```python
# tests/test_bridge_integration.py
import functools
from superlink.bridge.core import BridgeCore
from superlink.bridge.store import InMemoryDeviceStore
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.session import DeviceSession
from superlink.bridge.events import DeviceDiscovered, PropertyEvent
from fixtures.captured_frames import (
    SENSOR_MAC, DEFAULT_PAIRING_KEY, FRAME_36B_RAW,
)

GW_MAC = bytes.fromhex("0102030405")


def _core(auto_adopt):
    factory = functools.partial(_make_session)
    return BridgeCore(InMemoryDeviceStore(), ProfileRegistry.load(),
                      session_factory=factory, auto_adopt=auto_adopt)


def _make_session(record):
    return DeviceSession(record, gw_mac=GW_MAC, pairing_key=DEFAULT_PAIRING_KEY,
                         profiles=ProfileRegistry.load())


def test_unknown_frame_discovers():
    core = _core(auto_adopt=False)
    seen = []
    core.subscribe(seen.append)
    core.feed(FRAME_36B_RAW, channel=1, now=1.0)
    assert any(isinstance(e, DeviceDiscovered) and e.mac == SENSOR_MAC for e in seen)


def test_two_macs_no_crosstalk():
    core = _core(auto_adopt=True)
    other = bytearray(FRAME_36B_RAW)
    other[2:8] = bytes.fromhex("AABBCCDDEEFF")
    seen = []
    core.subscribe(seen.append)
    core.feed(FRAME_36B_RAW, channel=1, now=1.0)
    core.feed(bytes(other), channel=1, now=1.0)
    assert set(core._sessions.keys()) == {SENSOR_MAC, bytes.fromhex("AABBCCDDEEFF")}
```

- [ ] **Step 2: Run and iterate**

Run: `uv run pytest tests/test_bridge_integration.py -v`
Expected: initially may FAIL if the session's active-state decrypt path needs a restored session key for a not-yet-adopted device. If so, assert on discovery/routing (as written) rather than decrypted values — decrypted-value assertions belong to a fixture with a known session key. Adjust the test to the real surface, keep it green.

- [ ] **Step 3: Commit**

```bash
git add tests/test_bridge_integration.py tools/sx1302/superlink/bridge/core.py
git commit -m "test: end-to-end bridge core integration (discovery, multi-device routing)"
```

---

### Task 9: Rewire gateway.py runtime + RE sweep as observer

**Files:**
- Modify: `tools/sx1302/superlink/gateway.py` (`main()` and arg handling → drive `BridgeCore`)
- Create: `tools/sx1302/superlink/bridge/observers.py` (sweep adapter)
- Test: existing `tests/test_gateway.py` regression + `tests/test_bridge_observer.py`

**Interfaces:**
- Consumes: `BridgeCore`, `DeviceSession`, `superlink.sweep`.
- Produces: `SweepObserver` in `observers.py` — subscribes to core events and submits `RequestProperty`/`Ping`/`SetPropertyRaw` actions, reproducing today's `_ingest_app_report`-driven probe sequencing through the public API. `__init__(self, core: BridgeCore, sweep)`; method `on_event(self, event: Event) -> None`.

- [ ] **Step 1: Regression baseline**

Run: `uv run pytest tests/test_gateway.py -v`
Expected: PASS (record count).

- [ ] **Step 2: Write the observer test**

```python
# tests/test_bridge_observer.py
from superlink.bridge.observers import SweepObserver
from superlink.bridge.events import PropertyEvent

MAC = bytes.fromhex("9041B22E9A53")


class FakeSweep:
    def __init__(self):
        self.reports = []
        self.findings = []
        self.sizes = {}
    def record_report(self, report):
        self.reports.append(report)


class FakeCore:
    def __init__(self):
        self.submitted = []
    def submit(self, action):
        self.submitted.append(action)


def test_observer_forwards_property_events_to_sweep():
    core, sweep = FakeCore(), FakeSweep()
    obs = SweepObserver(core, sweep)
    obs.on_event(PropertyEvent(mac=MAC, property_id=3, name="BATTERY",
                               channel=0, raw=b"\x64", value=100, unit="%", decoded=True))
    assert len(sweep.reports) == 1
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_observer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.observers'`

- [ ] **Step 4: Implement observer + rewire main()**

Write `observers.py`:

```python
# tools/sx1302/superlink/bridge/observers.py
"""RE sweep re-expressed as a BridgeCore event observer + action injector."""
from __future__ import annotations
from .events import Event, PropertyEvent, DeviceInfoEvent, RequestProperty


class SweepObserver:
    def __init__(self, core, sweep):
        self.core = core
        self.sweep = sweep

    def on_event(self, event: Event) -> None:
        if isinstance(event, DeviceInfoEvent) and hasattr(self.sweep, "set_device_info"):
            self.sweep.set_device_info({
                "deviceType": event.device_type,
                "supportedProperties": event.supported_properties,
            })
        elif isinstance(event, PropertyEvent):
            self.sweep.record_report({"propertyId": event.property_id,
                                      "channel": event.channel,
                                      "value": event.raw})
```

Then rewrite `gateway.py:main()` to: build `ProfileRegistry`, `JsonDeviceStore`, a `DeviceSession` factory, and a `BridgeCore`; if `--reconnect`, the store already restores the record; if a `sweep` is configured, attach `SweepObserver` via `core.subscribe(obs.on_event)`; run the HAL RX/TX/tick loop calling `core.feed(raw, channel, now)` and `core.tick(now)` and transmitting each returned `OutgoingFrame`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_observer.py tests/test_gateway.py -v`
Expected: both PASS; `tests/test_gateway.py` count unchanged from Step 1.

- [ ] **Step 6: Full suite**

Run: `uv run pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add tools/sx1302/superlink/bridge/observers.py tools/sx1302/superlink/gateway.py tests/test_bridge_observer.py
git commit -m "refactor: gateway.py runs on BridgeCore; RE sweep is an observer"
```

---

## Self-Review

**Spec coverage:**
- Module layout (§Module layout): Tasks 1-7 create `events.py`, `core.py`, `session.py`, `profiles.py`, `profiles/superlink.yaml`, `store.py`; `mapping.py` and `observers.py` are additions justified by keeping `core.py`/`session.py` focused (spec's "one clear responsibility"). ✅
- Pure engine / injected time (§decision 3): `now: float` threaded through `feed`/`tick` (Tasks 6, 7). ✅
- Full multi-device lifecycle (§decision 4): registry keyed by MAC, discovery→adopt, `auto_adopt` (Task 6); persistence via store (Task 3). ✅
- Layered semantics + YAML profiles (§decision 5): Tasks 2, 5. ✅
- Events & actions (§4): Task 1 + encoders Task 4 + mapping Task 5. ✅
- Storage interface (§6): Task 3. ✅
- Migration of gateway.py + sweep as observer (§7): Tasks 7, 9. ✅
- Testing strategy (§8): event decode (Task 5/8), profile round-trips (Task 2), multi-device routing (Task 8), store round-trip (Task 3), discovery+adoption (Task 6), regression gate (Tasks 7, 9). ✅
- Success criteria: #1 decode (Task 5/8); #2 SetProperty byte-correctness (Task 5 `test_action_to_body_set_property`, with capture validation flagged as follow-up when a captured PROPERTY_SET exists); #3 two sensors (Task 8); #4 gateway+sweep on public API + green suite (Task 9); #5 add device = YAML edit (Task 2 design). ✅

**Placeholder scan:** No "TBD"/"add error handling"/"similar to Task N" — each code step is complete. The one flagged open item (validating `SetProperty` bytes against a real captured `PROPERTY_SET`) is called out explicitly as needing a capture, not left as a silent gap.

**Type consistency:** `OutgoingFrame(data, freq_hz, channel)` used identically in Tasks 6-9. `feed(frame|raw, channel, now)` returns `(frames, events)` at the session level and `list[OutgoingFrame]` at the core level — distinction stated in Tasks 6 and 7. `events_from_app_message(mac, body, profiles, sizes, device_type)` and `action_to_body(action, profiles, tag, device_type)` signatures match between Task 5 definition and Task 6/7 use. `ProfileRegistry.decode/encode/resolve_id/name` consistent across Tasks 2, 5, 6, 7.

**Known assumption to validate during execution:** application-layer multi-byte integer endianness is assumed big-endian (Global Constraints). Task 8/follow-up should confirm against a captured `PROPERTY_REPORT` with a known multi-byte value; if little-endian, it's a per-type field in the YAML, not an engine change.
