# SuperLink Bridge Runtime Daemon — Design Spec

**Date:** 2026-07-23
**Status:** Draft
**Scope:** Sub-project C of the open SuperLink bridge — a runtime daemon that
owns the SX1302 radio and drives the pure `BridgeCore` (sub-project A) against
real sensors: an RX-driven poll loop that translates received frames into
`core.feed()` and schedules the core's outgoing frames back onto the radio with
correct downlink timing, plus config, device-registry persistence, and an event
sink seam for the future MQTT adapter (sub-project B).

## Goal

Make sub-project A real on hardware. After this, someone can run
`superlink-bridged` on a Raspberry Pi + SX1302 CoreCell, list the sensor MACs
they own in a config file, and have the daemon pair with those sensors and
surface their events — with a clean in-process seam for sub-project B to publish
those events to MQTT / Home Assistant.

This spec covers **only** the runtime daemon. The MQTT adapter (B) is a separate
spec that attaches to the event sink defined here.

### Non-goals (deferred)

- MQTT / Home Assistant integration (sub-project B) — C only exposes the seam.
- Any protocol/wire change or new RE. C is pure glue over the existing
  `BridgeCore` + `SX1302` HAL.
- Beacon-based pairing. The proven real-hardware behavior is RX-driven (the
  sensor self-announces with `0x40`); C does not beacon.
- Interactive/live device approval UX — adoption is config-allowlist driven; the
  live-approval UX is B's job (it drives the same `AdoptDevice` action).

## Context: what already exists

- `bridge/core.py::BridgeCore` — pure engine: `feed(raw, channel, now) ->
  list[OutgoingFrame]`, `tick(now) -> list[OutgoingFrame]`, `submit(action)`,
  `subscribe(cb)`. Keyed by sensor MAC. `OutgoingFrame(data, freq_hz, channel)`
  carries **no timing** (deliberately — timing is a runtime concern).
- `bridge/session.py::DeviceSession(record, gw_mac, pairing_key, profiles)` —
  the per-sensor state machine; `to_record() -> DeviceRecord`.
- `bridge/store.py` — `DeviceStore` interface + `JsonDeviceStore(path)`.
- `bridge/profiles.py::ProfileRegistry.load()`.
- `bridge/events.py` — event/action dataclasses (`DeviceDiscovered`,
  `DeviceStateEvent`, `PropertyEvent`, `DeviceInfoEvent`, `AdoptDevice`, …).
- `hal.py::SX1302` — `start()`, `stop()`, `version()`, `receive() ->
  list[RxPacket]`, `send(freq_hz, payload, bandwidth=BW_500KHZ,
  tx_timestamp_us=..., invert_pol=...)`. `RxPacket` has `crc_ok`, `payload`,
  `ul_channel` (1–8), `timestamp_us` (concentrator hardware timestamp).
- Today's `gateway.py` runtime is RX-driven and schedules DL TX at
  `pkt.timestamp_us + tx_delay` (default `1_000_000` µs = 1 s, "matches real Ubi
  gateway"), with ordered multi-frame bursts spaced `500_000` µs apart. C
  reproduces that timing model over the core's returned frames.

## Architectural decisions (settled during brainstorming)

1. **Relationship to `gateway.py`:** a **new clean runtime**
   (`bridge/runtime.py` + a `superlink-bridged` entry). `gateway.py` is left
   untouched as the RE/fuzzing tool. One core, two consumers — mirrors
   sub-project A. The RE sweep and its probe-send hooks stay in `gateway.py` and
   are **not** C's concern.
2. **Timing model:** **RX-driven only.** Every `OutgoingFrame` returned by a
   given `core.feed(rx_pkt)` is treated as the response to that packet and
   scheduled at `rx_pkt.timestamp_us + downlink_delay_us` (multiple frames →
   sequential timestamps spaced `burst_spacing_us`). This keeps `OutgoingFrame`
   timing-free and the core pure — the RX↔TX correlation lives entirely in the
   runtime. `tick()` is used only for non-RF housekeeping (session timeouts).
3. **Adoption:** **config allowlist** of sensor MACs (or `adopt: all`). On
   `DeviceDiscovered`, the runtime submits `AdoptDevice` iff the MAC is allowed;
   otherwise it logs and ignores. Safe on a shared band; B later drives the same
   action interactively.
4. **Event output:** structured logging + optional CSV + an in-process
   `add_event_sink(callback)` seam that B attaches its MQTT publisher to.
5. **Persistence:** save a `DeviceRecord` (adopt keys + adopted flag) through the
   `DeviceStore` on the adoption-commit event; delete on removal. Per-frame seq
   counters are not persisted — reconnect re-handshakes for a fresh session key.

## Module layout

| Module | Role |
|--------|------|
| `tools/sx1302/superlink/bridge/config.py` | `RuntimeConfig` dataclass + YAML loader. |
| `tools/sx1302/superlink/bridge/runtime.py` | `BridgeRuntime` — HAL lifecycle, RX-driven loop, event sinks, persistence, hal↔core translation; `main()`. |
| `tools/sx1302/superlink-bridged` | Entry script: `from superlink.bridge.runtime import main; main()`. |
| `tools/sx1302/superlink_bridge.yaml.example` | Documented sample config. |

`gateway.py`, `bridge/*` (A), `hal.py` are unchanged dependencies.

## Component design

### `RuntimeConfig` (`config.py`)

YAML-loaded dataclass:

```yaml
gw_mac: "010203040506"          # 6-byte gateway MAC (hex)
pairing_key: null               # hex; null => documented default pairing key
store_path: "superlink_devices.json"
adopt: ["9041b22e9a53"]         # list of sensor MACs, or the string "all"
downlink_delay_us: 1000000      # DL TX offset after RX timestamp (default 1 s)
burst_spacing_us: 500000        # spacing between multiple DL frames in one response
invert_iq: false                # DL IQ inversion
log:
  level: "INFO"
  csv: null                     # optional CSV path for decoded events
```

- `load(path) -> RuntimeConfig`: parses/validates; `gw_mac` must be 6 bytes;
  `adopt` normalizes to a set of `bytes` MACs or the sentinel `ADOPT_ALL`;
  `pairing_key` defaults to the documented default when null.
- `is_allowed(mac: bytes) -> bool`: `adopt == ADOPT_ALL or mac in adopt_set`.

### `BridgeRuntime` (`runtime.py`)

Construction:
- `ProfileRegistry.load()`, `JsonDeviceStore(config.store_path)`,
  `BridgeCore(store, profiles, session_factory, auto_adopt=False)`.
- `session_factory(record) -> DeviceSession(record, gw_mac=config.gw_mac,
  pairing_key=config.pairing_key, profiles=profiles)`. Restored sessions come
  from `store.load_all()` in the `BridgeCore` constructor.
- The HAL is injected (`BridgeRuntime(config, hal, store=None)`), so tests pass a
  `FakeHal`. `main()` injects a real `SX1302`.

Event handling (one internal subscriber, `subscribe`d to the core):
- `DeviceDiscovered(mac)` → if `config.is_allowed(mac)`: `core.submit(
  AdoptDevice(mac))`; else `log.info("discovered %s — not in allowlist", mac)`.
- `DeviceStateEvent(mac, "adopted")` → `store.save(self._session(mac).to_record())`.
- `PropertyEvent` / `DeviceInfoEvent` → structured log, CSV row (if configured),
  and fan out to every registered event sink.

`add_event_sink(callback: Callable[[Event], None])` — registers an event
consumer (B's MQTT publisher attaches here). Built-in log/CSV are default sinks.

RX-driven poll loop (`run()`):

```
hal.start()
try:
    while not self._stop:
        for pkt in hal.receive():
            if not pkt.crc_ok: continue
            frames = core.feed(pkt.payload, pkt.ul_channel, now=monotonic())
            self._schedule(frames, base_ts=pkt.timestamp_us)
        self._maybe_tick(monotonic())     # housekeeping only, rare
        sleep(0.01)
finally:
    hal.stop(); flush CSV; final store save
```

`_schedule(frames, base_ts)`:

```
for i, f in enumerate(frames):
    ts = base_ts + downlink_delay_us + i * burst_spacing_us
    try:
        hal.send(f.freq_hz, f.data, bandwidth=BW_500KHZ,
                 tx_timestamp_us=ts, invert_pol=config.invert_iq)
    except (ValueError, RuntimeError) as exc:
        log.warning("TX skipped (%d bytes): %s", len(f.data), exc)   # never kill the loop
```

`_maybe_tick(now)` calls `core.tick(now)` at most every N seconds for session
timeouts; any returned frames are sent best-effort (immediate `tx_timestamp_us=0`).

Shutdown: `stop()` sets `self._stop`; `run()`'s `finally` stops the HAL, flushes
CSV, and does a final `store.save` for every adopted session.

### Entry point & deploy

`superlink-bridged` mirrors `superlink-gw`. `main()` parses `--config PATH`
(default `superlink_bridge.yaml`), builds `RuntimeConfig`, a real `SX1302`, and a
`BridgeRuntime`, and calls `run()`. Add `deploy.sh run bridged` to the Pi run
options (the package is already rsynced).

## Testing strategy

The HAL loop needs hardware, but all runtime **logic** is tested with a
`FakeHal` (implements `start/stop/version/receive/send`; `receive()` yields
canned `RxPacket`s; `send()` records `(freq_hz, payload, tx_timestamp_us,
invert_pol)` calls). No Pi required.

- **Allowlist adopt:** feed a `DeviceDiscovered` for an in-list MAC → the runtime
  submits `AdoptDevice`; a not-in-list MAC → no adopt, logged. `adopt: all`
  adopts any.
- **DL scheduling:** a `core.feed` that returns 2 `OutgoingFrame`s (drive a real
  `DeviceSession` through discover→adopt→`0x42` using captured fixtures, which
  emits handshake frames) → the runtime issues `hal.send` calls at
  `rx_ts + downlink_delay_us` and `rx_ts + downlink_delay_us + burst_spacing_us`,
  with `invert_pol` from config.
- **TX-error resilience:** a `FakeHal.send` that raises `RuntimeError` on one
  frame → the loop logs and continues, still sends the others.
- **Persistence:** on the adopted `DeviceStateEvent`, `store.save` is called with
  a `DeviceRecord` carrying the adopt keys; a fresh `BridgeRuntime` over the same
  store restores the session (present in `core._sessions`).
- **Event-sink fan-out:** a registered sink receives `PropertyEvent`s; CSV rows
  are written when configured.
- **Config load:** YAML → `RuntimeConfig` with parsed `gw_mac` bytes, allowlist
  set vs `ADOPT_ALL`, and the numeric defaults; invalid `gw_mac` length raises.
- **Bench validation (manual, flagged):** deploy to the Pi, add a real sensor MAC
  to `adopt`, and confirm the sensor pairs and its events are logged — the true
  end-to-end proof, not automated here.

## Success criteria

1. With a `FakeHal`, an allowlisted sensor's captured `0x40`→`0x42` sequence
   drives the core to emit a handshake frame, and the runtime schedules it at
   `rx_ts + downlink_delay_us` with the configured IQ inversion.
2. A discovered non-allowlisted MAC is not adopted (logged only).
3. The adoption-commit event persists a `DeviceRecord`; a restart over the same
   store reloads it and the session resumes.
4. `PropertyEvent`s reach a registered event sink and the CSV, proving the B seam
   and the visible output.
5. A `TX` failure on one frame never kills the loop.
6. `superlink-bridged` runs on the Pi against a real sensor (bench-validated,
   manual).
