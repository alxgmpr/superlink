# SuperLink Bridge Runtime Daemon Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `superlink-bridged` — a runtime daemon that owns the SX1302 radio and drives the pure `BridgeCore` against real sensors: RX-driven poll loop, downlink-timed TX scheduling, config allowlist adoption, device-registry persistence, and an event-sink seam for the future MQTT adapter.

**Architecture:** A new `bridge/runtime.py` (`BridgeRuntime`) + `bridge/config.py` (`RuntimeConfig`) + a `superlink-bridged` entry script. The HAL is injected so all logic is tested with a `FakeHal`; the core is unchanged. `gateway.py` is left alone as the RE tool.

**Tech Stack:** Python 3.11+, `PyYAML`, `pytest`. Managed with `uv`.

## Global Constraints

- Python tooling is **`uv` only**; run tests with `uv run pytest tests/...` from repo root `/Users/alex/superlink`. Never raw `pip`/`python -m venv`.
- New code lives under `tools/sx1302/superlink/bridge/`; import as `from superlink.bridge... import ...`. Run pytest from repo root (conftest puts `tools/sx1302` + repo root on `sys.path`).
- **Do NOT modify sub-project A** (`bridge/core.py`, `session.py`, `store.py`, `profiles.py`, `events.py`, `mapping.py`) or `gateway.py` or `hal.py`. C is pure glue on top.
- **DL timing model (exact):** frames returned by `core.feed(rx_pkt)` are scheduled at `rx_pkt.timestamp_us + downlink_delay_us + i * burst_spacing_us` for the i-th frame. Defaults: `downlink_delay_us = 1_000_000`, `burst_spacing_us = 500_000`, `invert_iq = False`.
- **A TX error must never kill the loop** — catch `(ValueError, RuntimeError)` around each `hal.send`, log, and continue.
- The documented default pairing key is `47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe`.
- Full suite must stay green except the 2 known-accepted `test_gateway.py` ConnectionChallenge failures. Commit after every task.

---

### Task 1: RuntimeConfig + YAML loader

**Files:**
- Create: `tools/sx1302/superlink/bridge/config.py`
- Test: `tests/test_bridge_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `ADOPT_ALL` — module-level sentinel.
  - `DEFAULT_PAIRING_KEY: bytes`.
  - `RuntimeConfig` dataclass: `gw_mac: bytes`, `pairing_key: bytes`, `store_path: str`, `adopt` (a `set[bytes]` or `ADOPT_ALL`), `downlink_delay_us: int = 1_000_000`, `burst_spacing_us: int = 500_000`, `invert_iq: bool = False`, `log_level: str = "INFO"`, `csv_path: str | None = None`.
  - `RuntimeConfig.load(path: str) -> RuntimeConfig`.
  - `RuntimeConfig.is_allowed(self, mac: bytes) -> bool`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_config.py
import pytest
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY

YAML_LIST = """
gw_mac: "010203040506"
pairing_key: null
store_path: "devs.json"
adopt: ["9041b22e9a53", "AABBCCDDEEFF"]
downlink_delay_us: 900000
invert_iq: true
log:
  level: "DEBUG"
  csv: "events.csv"
"""

YAML_ALL = """
gw_mac: "010203040506"
adopt: all
"""


def _write(tmp_path, text):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    return str(p)


def test_load_list(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_LIST))
    assert c.gw_mac == bytes.fromhex("010203040506")
    assert c.pairing_key == DEFAULT_PAIRING_KEY        # null -> default
    assert c.adopt == {bytes.fromhex("9041b22e9a53"), bytes.fromhex("aabbccddeeff")}
    assert c.downlink_delay_us == 900000
    assert c.burst_spacing_us == 500000                 # default
    assert c.invert_iq is True
    assert c.log_level == "DEBUG" and c.csv_path == "events.csv"


def test_is_allowed_list(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_LIST))
    assert c.is_allowed(bytes.fromhex("9041b22e9a53")) is True
    assert c.is_allowed(bytes.fromhex("001122334455")) is False


def test_adopt_all(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_ALL))
    assert c.adopt is ADOPT_ALL
    assert c.is_allowed(bytes.fromhex("001122334455")) is True


def test_bad_gw_mac(tmp_path):
    with pytest.raises(ValueError):
        RuntimeConfig.load(_write(tmp_path, 'gw_mac: "0102"\nadopt: all\n'))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.config'`

- [ ] **Step 3: Write the implementation**

```python
# tools/sx1302/superlink/bridge/config.py
"""Runtime configuration for the SuperLink bridge daemon."""
from __future__ import annotations
from dataclasses import dataclass, field
import yaml

# Documented Ubiquiti factory-default pairing key (docs/protocol/crypto_and_pairing.md).
DEFAULT_PAIRING_KEY = bytes.fromhex(
    "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
)

ADOPT_ALL = object()  # sentinel: adopt any discovered device


@dataclass
class RuntimeConfig:
    gw_mac: bytes
    pairing_key: bytes = DEFAULT_PAIRING_KEY
    store_path: str = "superlink_devices.json"
    adopt: object = field(default_factory=set)   # set[bytes] or ADOPT_ALL
    downlink_delay_us: int = 1_000_000
    burst_spacing_us: int = 500_000
    invert_iq: bool = False
    log_level: str = "INFO"
    csv_path: str | None = None

    @classmethod
    def load(cls, path: str) -> "RuntimeConfig":
        with open(path) as f:
            doc = yaml.safe_load(f) or {}

        gw_mac = bytes.fromhex(doc["gw_mac"])
        if len(gw_mac) != 6:
            raise ValueError(f"gw_mac must be 6 bytes, got {len(gw_mac)}")

        pk = doc.get("pairing_key")
        pairing_key = bytes.fromhex(pk) if pk else DEFAULT_PAIRING_KEY

        raw_adopt = doc.get("adopt", [])
        if isinstance(raw_adopt, str) and raw_adopt.lower() == "all":
            adopt: object = ADOPT_ALL
        else:
            adopt = {bytes.fromhex(m) for m in raw_adopt}

        log = doc.get("log") or {}
        return cls(
            gw_mac=gw_mac,
            pairing_key=pairing_key,
            store_path=doc.get("store_path", "superlink_devices.json"),
            adopt=adopt,
            downlink_delay_us=int(doc.get("downlink_delay_us", 1_000_000)),
            burst_spacing_us=int(doc.get("burst_spacing_us", 500_000)),
            invert_iq=bool(doc.get("invert_iq", False)),
            log_level=log.get("level", "INFO"),
            csv_path=log.get("csv"),
        )

    def is_allowed(self, mac: bytes) -> bool:
        return self.adopt is ADOPT_ALL or mac in self.adopt
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_config.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/config.py tests/test_bridge_config.py
git commit -m "feat: runtime config with YAML loader and adopt allowlist"
```

---

### Task 2: BridgeRuntime — wiring, event handling, sinks, persistence

**Files:**
- Create: `tools/sx1302/superlink/bridge/runtime.py`
- Create: `tests/support/fake_hal.py`
- Test: `tests/test_bridge_runtime_events.py`

**Interfaces:**
- Consumes: `RuntimeConfig`, `BridgeCore`, `DeviceSession`, `ProfileRegistry`, `InMemoryDeviceStore`/`JsonDeviceStore`, event/action types.
- Produces:
  - `FakeHal` (test support): `start()`, `stop()`, `version()->str`, `receive()->list`, `send(freq_hz, payload, bandwidth=..., tx_timestamp_us=..., invert_pol=...)` recording calls in `self.sent`. `receive()` returns and clears a queued `self.inbox`.
  - `BridgeRuntime(config: RuntimeConfig, hal, store: DeviceStore | None = None)` with: `core` (a `BridgeCore`), `add_event_sink(cb)`, and an internal `_on_event(event)` subscribed to the core. The `session_factory` records each built `DeviceSession` in `self._sessions[record.mac]`. On construction, `store=None` → `JsonDeviceStore(config.store_path)`.

- [ ] **Step 1: Write the FakeHal support module**

```python
# tests/support/__init__.py
```
```python
# tests/support/fake_hal.py
"""In-memory HAL double for runtime tests. Records sends; replays a queued inbox."""
from types import SimpleNamespace


def make_packet(payload: bytes, ul_channel: int = 1, timestamp_us: int = 1000,
                crc_ok: bool = True):
    """Minimal stand-in exposing the 4 attrs BridgeRuntime reads off an RxPacket."""
    return SimpleNamespace(payload=payload, ul_channel=ul_channel,
                           timestamp_us=timestamp_us, crc_ok=crc_ok)


class FakeHal:
    def __init__(self, inbox=None, fail_on_send_index=None):
        self.inbox = list(inbox or [])
        self.sent = []            # list of dicts
        self.started = False
        self.stopped = False
        self._fail_idx = fail_on_send_index

    def start(self, *a, **k):
        self.started = True

    def stop(self):
        self.stopped = True

    def version(self):
        return "fake-hal"

    def receive(self):
        pkts, self.inbox = self.inbox, []
        return pkts

    def send(self, freq_hz, payload, bandwidth=None, tx_timestamp_us=0,
             invert_pol=False):
        idx = len(self.sent)
        if self._fail_idx is not None and idx == self._fail_idx:
            raise RuntimeError("simulated lgw_send failure")
        self.sent.append({"freq_hz": freq_hz, "payload": bytes(payload),
                          "tx_timestamp_us": tx_timestamp_us,
                          "invert_pol": invert_pol})
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_bridge_runtime_events.py
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore, DeviceRecord
from superlink.bridge.events import (
    DeviceDiscovered, DeviceStateEvent, PropertyEvent, AdoptDevice,
)
from tests.support.fake_hal import FakeHal

MAC = bytes.fromhex("9041B22E9A53")
OTHER = bytes.fromhex("001122334455")


def _cfg(adopt):
    return RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                         pairing_key=DEFAULT_PAIRING_KEY, adopt=adopt)


def _runtime(adopt, store=None):
    return BridgeRuntime(_cfg(adopt), FakeHal(), store=store or InMemoryDeviceStore())


def test_discovered_allowed_mac_is_adopted():
    rt = _runtime({MAC})
    submitted = []
    rt.core.submit = lambda a: submitted.append(a)   # capture submits
    rt._on_event(DeviceDiscovered(mac=MAC, channel=1, first_seen=1.0))
    assert any(isinstance(a, AdoptDevice) and a.mac == MAC for a in submitted)


def test_discovered_disallowed_mac_is_not_adopted():
    rt = _runtime({MAC})
    submitted = []
    rt.core.submit = lambda a: submitted.append(a)
    rt._on_event(DeviceDiscovered(mac=OTHER, channel=1, first_seen=1.0))
    assert submitted == []


def test_adopt_all():
    rt = _runtime(ADOPT_ALL)
    submitted = []
    rt.core.submit = lambda a: submitted.append(a)
    rt._on_event(DeviceDiscovered(mac=OTHER, channel=1, first_seen=1.0))
    assert len(submitted) == 1


def test_adopted_state_persists_record():
    store = InMemoryDeviceStore()
    rt = _runtime({MAC}, store=store)
    # Simulate a session the core built for this mac.
    rt._sessions[MAC] = _FakeSession(MAC)
    rt._on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    saved = store.load_all()
    assert len(saved) == 1 and saved[0].mac == MAC


def test_property_event_reaches_sink():
    rt = _runtime({MAC})
    seen = []
    rt.add_event_sink(seen.append)
    ev = PropertyEvent(mac=MAC, property_id=3, name="BATTERY", channel=0,
                       raw=b"\x64", value=100, unit="%", decoded=True)
    rt._on_event(ev)
    assert ev in seen


class _FakeSession:
    def __init__(self, mac):
        self._mac = mac
    def to_record(self):
        return DeviceRecord(mac=self._mac, adopted=True)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_runtime_events.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'superlink.bridge.runtime'`

- [ ] **Step 4: Write the implementation**

```python
# tools/sx1302/superlink/bridge/runtime.py
"""SuperLink bridge runtime daemon: owns the SX1302 HAL and drives BridgeCore."""
from __future__ import annotations
import csv
import logging
import time
from typing import Callable

from ..hal import BW_500KHZ
from .config import RuntimeConfig
from .core import BridgeCore, OutgoingFrame
from .events import (
    Event, DeviceDiscovered, DeviceStateEvent, PropertyEvent, DeviceInfoEvent,
    AdoptDevice,
)
from .profiles import ProfileRegistry
from .session import DeviceSession
from .store import DeviceStore, JsonDeviceStore

log = logging.getLogger("superlink.runtime")


class BridgeRuntime:
    def __init__(self, config: RuntimeConfig, hal, store: DeviceStore | None = None):
        self.config = config
        self.hal = hal
        self.profiles = ProfileRegistry.load()
        self.store = store if store is not None else JsonDeviceStore(config.store_path)
        self._sessions: dict[bytes, DeviceSession] = {}
        self._sinks: list[Callable[[Event], None]] = []
        self._stop = False
        self._csv_writer = None
        self._csv_file = None
        self.core = BridgeCore(self.store, self.profiles, self._session_factory,
                               auto_adopt=False)
        self.core.subscribe(self._on_event)

    def _session_factory(self, record) -> DeviceSession:
        s = DeviceSession(record, gw_mac=self.config.gw_mac,
                          pairing_key=self.config.pairing_key,
                          profiles=self.profiles)
        self._sessions[record.mac] = s
        return s

    def add_event_sink(self, callback: Callable[[Event], None]) -> None:
        self._sinks.append(callback)

    def _on_event(self, event: Event) -> None:
        if isinstance(event, DeviceDiscovered):
            if self.config.is_allowed(event.mac):
                log.info("discovered %s — adopting", event.mac.hex())
                self.core.submit(AdoptDevice(mac=event.mac))
            else:
                log.info("discovered %s — not in allowlist, ignoring", event.mac.hex())
        elif isinstance(event, DeviceStateEvent) and event.state == "adopted":
            session = self._sessions.get(event.mac)
            if session is not None:
                self.store.save(session.to_record())
                log.info("persisted adopted device %s", event.mac.hex())
        elif isinstance(event, (PropertyEvent, DeviceInfoEvent)):
            self._log_and_csv(event)
        # Every event fans out to sinks (B's MQTT publisher attaches here).
        for sink in self._sinks:
            sink(event)

    def _log_and_csv(self, event: Event) -> None:
        if isinstance(event, PropertyEvent):
            log.info("%s %s[ch%d] = %s%s", event.mac.hex(), event.name,
                     event.channel, event.value if event.decoded else event.raw.hex(),
                     f" {event.unit}" if event.unit else "")
            if self._csv_writer is not None:
                self._csv_writer.writerow([
                    time.time(), event.mac.hex(), event.name, event.channel,
                    event.value if event.decoded else "", event.raw.hex(),
                    event.unit or "", event.decoded])
                self._csv_file.flush()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_runtime_events.py -v`
Expected: PASS (5 passed)

- [ ] **Step 6: Commit**

```bash
git add tools/sx1302/superlink/bridge/runtime.py tests/support/ tests/test_bridge_runtime_events.py
git commit -m "feat: BridgeRuntime wiring, allowlist adoption, event sinks, persistence"
```

---

### Task 3: RX-driven poll loop + DL scheduling

**Files:**
- Modify: `tools/sx1302/superlink/bridge/runtime.py` (add `poll_once`, `_schedule`, `_maybe_tick`, `run`, `stop`)
- Test: `tests/test_bridge_runtime_loop.py`

**Interfaces:**
- Consumes: everything from Task 2 + the captured fixtures.
- Produces (added to `BridgeRuntime`):
  - `poll_once(now: float) -> None` — drain `hal.receive()`, `core.feed` each crc-ok packet, schedule the returned frames.
  - `_schedule(frames: list[OutgoingFrame], base_ts: int) -> None` — `hal.send` each at `base_ts + downlink_delay_us + i*burst_spacing_us`, catching `(ValueError, RuntimeError)`.
  - `_maybe_tick(now: float) -> None`, `run() -> None`, `stop() -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_runtime_loop.py
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.core import OutgoingFrame
from superlink.bridge.store import InMemoryDeviceStore
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.session import DeviceSession
from tests.support.fake_hal import FakeHal, make_packet
from tests.fixtures.captured_frames import (
    DISCOVERY_FRAME_RAW, CONN_CHALLENGE_RAW, SENSOR_MAC,
)

GW = bytes.fromhex("010203040506")


def _cfg(adopt=ADOPT_ALL, delay=1_000_000, spacing=500_000):
    return RuntimeConfig(gw_mac=GW, pairing_key=DEFAULT_PAIRING_KEY, adopt=adopt,
                         downlink_delay_us=delay, burst_spacing_us=spacing)


def test_schedule_timestamps_and_burst_spacing():
    rt = BridgeRuntime(_cfg(), FakeHal(), store=InMemoryDeviceStore())
    frames = [OutgoingFrame(data=b"\xe0\x62aaa", freq_hz=920_400_000, channel=1),
              OutgoingFrame(data=b"\xe0\x63bbb", freq_hz=920_400_000, channel=1)]
    rt._schedule(frames, base_ts=1000)
    sent = rt.hal.sent
    assert len(sent) == 2
    assert sent[0]["tx_timestamp_us"] == 1000 + 1_000_000
    assert sent[1]["tx_timestamp_us"] == 1000 + 1_000_000 + 500_000


def test_schedule_tx_error_does_not_kill_loop():
    hal = FakeHal(fail_on_send_index=0)
    rt = BridgeRuntime(_cfg(), hal, store=InMemoryDeviceStore())
    frames = [OutgoingFrame(data=b"x", freq_hz=1, channel=1),
              OutgoingFrame(data=b"y", freq_hz=2, channel=1)]
    rt._schedule(frames, base_ts=0)          # first send raises, must be swallowed
    assert len(hal.sent) == 1 and hal.sent[0]["payload"] == b"y"


def test_poll_once_ignores_bad_crc():
    rt = BridgeRuntime(_cfg(), FakeHal(inbox=[make_packet(b"\x00" * 20, crc_ok=False)]),
                       store=InMemoryDeviceStore())
    rt.poll_once(now=1.0)
    assert rt.hal.sent == []


def test_poll_once_drives_real_session_to_emit_0x62():
    """End-to-end: an allowlisted sensor's 0x40 then 0x42 through poll_once must
    result in a scheduled 0x62 send at rx_ts + downlink_delay_us."""
    def factory(record):
        return DeviceSession(record, gw_mac=GW, pairing_key=DEFAULT_PAIRING_KEY,
                             profiles=ProfileRegistry.load())
    hal = FakeHal(inbox=[make_packet(DISCOVERY_FRAME_RAW, ul_channel=1, timestamp_us=5000)])
    rt = BridgeRuntime(_cfg(adopt=ADOPT_ALL), hal, store=InMemoryDeviceStore())
    rt.poll_once(now=1.0)                     # discover + auto-adopt + first response
    # feed the ConnectionChallenge next
    hal.inbox = [make_packet(CONN_CHALLENGE_RAW, ul_channel=1, timestamp_us=9000)]
    rt.poll_once(now=2.0)
    assert any(s["payload"][1] == 0x62 for s in hal.sent), "no 0x62 scheduled"
    chal = [s for s in hal.sent if s["payload"][1] == 0x62][-1]
    assert chal["tx_timestamp_us"] == 9000 + 1_000_000
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_runtime_loop.py -v`
Expected: FAIL with `AttributeError: 'BridgeRuntime' object has no attribute '_schedule'`

- [ ] **Step 3: Write the implementation (append to `runtime.py`)**

```python
    # --- append these methods to BridgeRuntime ---

    def _schedule(self, frames, base_ts: int) -> None:
        for i, f in enumerate(frames):
            ts = base_ts + self.config.downlink_delay_us + i * self.config.burst_spacing_us
            try:
                self.hal.send(f.freq_hz, f.data, bandwidth=BW_500KHZ,
                              tx_timestamp_us=ts, invert_pol=self.config.invert_iq)
            except (ValueError, RuntimeError) as exc:
                log.warning("TX skipped (%d bytes): %s", len(f.data), exc)

    def poll_once(self, now: float) -> None:
        for pkt in self.hal.receive():
            if not pkt.crc_ok:
                continue
            frames = self.core.feed(pkt.payload, pkt.ul_channel, now)
            self._schedule(frames, base_ts=pkt.timestamp_us)

    def _maybe_tick(self, now: float) -> None:
        # Housekeeping only (session timeouts). No RX packet to correlate, so any
        # frames go out best-effort/immediate.
        frames = self.core.tick(now)
        for f in frames:
            try:
                self.hal.send(f.freq_hz, f.data, bandwidth=BW_500KHZ,
                              tx_timestamp_us=0, invert_pol=self.config.invert_iq)
            except (ValueError, RuntimeError) as exc:
                log.warning("tick TX skipped: %s", exc)

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        if self.config.csv_path:
            self._csv_file = open(self.config.csv_path, "a", newline="")
            self._csv_writer = csv.writer(self._csv_file)
        self.hal.start()
        log.info("bridge runtime started (HAL %s)", self.hal.version())
        try:
            while not self._stop:
                self.poll_once(time.monotonic())
                time.sleep(0.01)
        except KeyboardInterrupt:
            log.info("shutting down")
        finally:
            self.hal.stop()
            for mac, session in self._sessions.items():
                try:
                    self.store.save(session.to_record())
                except Exception:  # best-effort final flush
                    pass
            if self._csv_file:
                self._csv_file.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_runtime_loop.py -v`
Expected: PASS (4 passed). If the real-session test needs the session ticked once to reach BEACONING before the ConnectionChallenge, note that `core.feed` lazily starts sessions (Task from sub-project A), so the first `poll_once` on the discovery frame both adopts and starts — no extra tick needed. If the 0x62 does not appear, do NOT weaken the assertion; investigate whether the discovery frame's mac matches SENSOR_MAC and the adopt path ran.

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/runtime.py tests/test_bridge_runtime_loop.py
git commit -m "feat: RX-driven poll loop with downlink-timed TX scheduling"
```

---

### Task 4: Entry point, example config, deploy

**Files:**
- Modify: `tools/sx1302/superlink/bridge/runtime.py` (add `build_runtime` + `main`)
- Create: `tools/sx1302/superlink-bridged`
- Create: `tools/sx1302/superlink_bridge.yaml.example`
- Modify: `tools/sx1302/deploy.sh` (add a `run bridged` option)
- Test: `tests/test_bridge_runtime_main.py`

**Interfaces:**
- Produces: `build_runtime(config: RuntimeConfig, hal) -> BridgeRuntime` (factory used by both `main` and tests) and `main(argv=None)` that parses `--config PATH`, builds a real `SX1302`, and calls `run()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_runtime_main.py
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import build_runtime, BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore
from tests.support.fake_hal import FakeHal


def test_build_runtime_wires_core_and_hal():
    cfg = RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                        pairing_key=DEFAULT_PAIRING_KEY, adopt=ADOPT_ALL)
    hal = FakeHal()
    rt = build_runtime(cfg, hal, store=InMemoryDeviceStore())
    assert isinstance(rt, BridgeRuntime)
    assert rt.hal is hal and rt.core is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bridge_runtime_main.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_runtime'`

- [ ] **Step 3: Write the implementation**

Append to `runtime.py`:

```python
def build_runtime(config: RuntimeConfig, hal, store=None) -> BridgeRuntime:
    return BridgeRuntime(config, hal, store=store)


def main(argv=None):
    import argparse
    from ..hal import SX1302
    parser = argparse.ArgumentParser(description="SuperLink bridge runtime daemon")
    parser.add_argument("--config", default="superlink_bridge.yaml",
                        help="path to YAML config")
    args = parser.parse_args(argv)
    config = RuntimeConfig.load(args.config)
    logging.basicConfig(level=getattr(logging, config.log_level, logging.INFO))
    runtime = build_runtime(config, SX1302())
    runtime.run()
```

Create `tools/sx1302/superlink-bridged` (mode 755):

```python
#!/usr/bin/env python3
"""SuperLink bridge runtime daemon."""
from superlink.bridge.runtime import main
main()
```

Create `tools/sx1302/superlink_bridge.yaml.example`:

```yaml
# SuperLink bridge daemon config. Copy to superlink_bridge.yaml and edit.
gw_mac: "010203040506"        # this bridge's 6-byte gateway MAC (hex)
pairing_key: null             # null => Ubiquiti factory-default pairing key
store_path: "superlink_devices.json"
adopt:                        # sensor MACs this bridge owns; or the string: all
  - "9041b22e9a53"
downlink_delay_us: 1000000    # DL TX offset after the RX hardware timestamp (1 s)
burst_spacing_us: 500000      # spacing between multiple DL frames in one response
invert_iq: false
log:
  level: "INFO"
  csv: null                   # optional path to append decoded events as CSV
```

In `tools/sx1302/deploy.sh`, add a `bridged` case alongside the existing `gw`/sniffer run options so `./deploy.sh run bridged` launches `superlink-bridged` on the Pi. Match the existing run-dispatch style in that script (read it first; mirror how `run gw` invokes `superlink-gw`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bridge_runtime_main.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Full suite + make entry executable**

Run: `chmod +x tools/sx1302/superlink-bridged && uv run pytest tests/ -q`
Expected: only the 2 known-accepted `test_gateway.py` failures fail; everything else green.

- [ ] **Step 6: Commit**

```bash
git add tools/sx1302/superlink/bridge/runtime.py tools/sx1302/superlink-bridged \
        tools/sx1302/superlink_bridge.yaml.example tools/sx1302/deploy.sh \
        tests/test_bridge_runtime_main.py
git commit -m "feat: superlink-bridged entry point, example config, deploy option"
```

---

## Self-Review

**Spec coverage:**
- Module layout (§Module layout): `config.py` (Task 1), `runtime.py` (Tasks 2–4), `superlink-bridged` + example config + deploy (Task 4). ✅
- RX-driven timing model (§decision 2): `_schedule` uses `base_ts + downlink_delay_us + i*burst_spacing_us`; `poll_once` correlates to the RX packet; `tick` best-effort (Task 3). ✅
- Allowlist adoption (§decision 3): `is_allowed` (Task 1) + `_on_event` DeviceDiscovered path (Task 2). ✅
- Event sinks (§decision 4): `add_event_sink` + fan-out + CSV (Task 2). ✅
- Persistence (§decision 5): `_session_factory` records sessions; adopted `DeviceStateEvent` → `store.save(to_record())` (Task 2); final flush in `run()` (Task 3). ✅
- New runtime, gateway.py untouched (§decision 1): no gateway.py edits anywhere. ✅
- Testing strategy (§Testing): FakeHal (Task 2), allowlist/scheduling/TX-error/persistence/sink/config tests (Tasks 1–3), real-session-to-0x62 integration (Task 3), config load (Task 1). ✅
- Success criteria: #1 real-session 0x62 scheduled at rx_ts+delay (Task 3 `test_poll_once_drives_real_session_to_emit_0x62`); #2 non-allowlisted not adopted (Task 2); #3 persist + restore (Task 2 persist; restore via BridgeCore ctor over the same store — covered by A's construction, exercised in Task 2's store); #4 sink + CSV (Task 2); #5 TX failure resilience (Task 3); #6 bench (manual, flagged). ✅

**Placeholder scan:** none — all steps carry complete code. The one judgment note (Task 3 Step 4, "if 0x62 doesn't appear, investigate, don't weaken") is guidance, not a placeholder.

**Type consistency:** `RuntimeConfig` field names (`downlink_delay_us`, `burst_spacing_us`, `invert_iq`, `is_allowed`, `adopt`/`ADOPT_ALL`) are identical across Tasks 1–4. `BridgeRuntime(config, hal, store=None)`, `_on_event`, `_schedule(frames, base_ts)`, `poll_once(now)`, `add_event_sink`, `_session_factory` consistent between definition (Tasks 2–3) and use (Tasks 3–4). `OutgoingFrame(data, freq_hz, channel)` and `hal.send(freq_hz, payload, bandwidth, tx_timestamp_us, invert_pol)` match the real sub-project A / `hal.py` signatures. `FakeHal.send` mirrors that signature.

**Note for execution:** Task 3's real-session integration test depends on sub-project A's lazy-start (`core.feed` starts an adopted session) and the `[3:35]` ConnectionChallenge handling — both already merged. It reuses `DISCOVERY_FRAME_RAW` / `CONN_CHALLENGE_RAW` fixtures (both real captures for `SENSOR_MAC`).
