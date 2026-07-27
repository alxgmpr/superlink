# Reconnect connection-manager — Track B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `superlink-bridged` recover from a sensor reconnect cleanly — no tight teardown loop, no permanent stranding — using telemetry as the liveness signal, plus auto-re-adopt when a sensor is factory-reset.

**Architecture:** Treat 0x54/0x44 telemetry as the "link healthy" heartbeat in `DeviceSession`. When an ACTIVE session stops hearing telemetry for `link_lost_timeout` seconds, it drops back to BEACONING (a time-driven `tick()` transition) so the sensor's next `0x40` discovery re-handshakes normally via `_handle_beaconing`. Because the drop is gated by a timeout (not per-`0x40`), re-handshakes are naturally rate-limited — the fix for the earlier teardown loop. A loop-guard backs off if re-handshakes never recover telemetry, and an unadopted-form `0x40` on an adopted session triggers auto-re-adopt.

**Tech Stack:** Python 3.14, pytest. Pure `DeviceSession` state machine (no I/O) + `BridgeRuntime` loop wiring. venv at repo `.venv`; run tests with `source .venv/bin/activate && python -m pytest`.

## Global Constraints

- Tests import via `superlink.*` (conftest adds `tools/sx1302` to `sys.path`).
- `DeviceSession` is pure/no-I/O; all time comes in as a `now: float` argument. `Date.now`-style calls are forbidden in the session.
- Preserve behavior for the existing 210-test suite; every task ends green.
- Frame direction/opcodes: `0x40`=discovery(UL), `0x42`=ConnChallenge, `0x53`=mgmt/command poll, `0x54`/`0x44`=data(telemetry). `dctrl` is cleartext (readable pre-decrypt).
- `DEVICE_STATES = ("discovered","adopting","adopted","active","lost")` — reuse `"lost"`; do not invent new state strings without adding them here.

---

### Task 1: Runtime drives `tick()` on a timer

Today `BridgeRuntime.run()` only calls `poll_once`; `_maybe_tick` exists but is never invoked, so nothing time-driven (beacons, the new liveness timeout) ever fires. Add interval-gated ticking.

**Files:**
- Modify: `tools/sx1302/superlink/bridge/runtime.py` (`BridgeRuntime.__init__`, `run`; add `tick_if_due`)
- Test: `tests/test_bridge_runtime_loop.py`

**Interfaces:**
- Consumes: `self._maybe_tick(now)` (exists), `self.core.tick(now)`.
- Produces: `BridgeRuntime.tick_if_due(now: float) -> None` — calls `_maybe_tick(now)` at most once per `self._tick_interval` seconds; `self._tick_interval: float` (default 1.0); `self._last_tick: float`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_runtime_loop.py  (add)
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore
from tests.support.fake_hal import FakeHal

def _rt():
    cfg = RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                        pairing_key=DEFAULT_PAIRING_KEY, adopt=ADOPT_ALL)
    return BridgeRuntime(cfg, FakeHal(), store=InMemoryDeviceStore())

def test_tick_if_due_calls_maybe_tick_at_most_once_per_interval():
    rt = _rt()
    calls = []
    rt._maybe_tick = lambda now: calls.append(now)
    rt._tick_interval = 1.0
    rt.tick_if_due(now=100.0)      # first call: due (last_tick starts at 0)
    rt.tick_if_due(now=100.5)      # within interval: skipped
    rt.tick_if_due(now=101.1)      # interval elapsed: due
    assert calls == [100.0, 101.1]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_runtime_loop.py::test_tick_if_due_calls_maybe_tick_at_most_once_per_interval -v`
Expected: FAIL with `AttributeError: 'BridgeRuntime' object has no attribute 'tick_if_due'`

- [ ] **Step 3: Write minimal implementation**

In `BridgeRuntime.__init__` (after `self._action_queue = queue.Queue()`), add:

```python
        self._tick_interval = 1.0
        self._last_tick = 0.0
```

Add the method (near `_maybe_tick`):

```python
    def tick_if_due(self, now: float) -> None:
        if now - self._last_tick >= self._tick_interval:
            self._last_tick = now
            self._maybe_tick(now)
```

In `run()`, change the loop body to tick each iteration:

```python
            while not self._stop:
                now = time.monotonic()
                self.poll_once(now)
                self.tick_if_due(now)
                time.sleep(0.01)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_runtime_loop.py -v`
Expected: PASS (all tests in file)

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/runtime.py tests/test_bridge_runtime_loop.py
git commit -m "feat(bridge): drive tick() on a timer in the runtime loop"
```

---

### Task 2: Telemetry-liveness timeout (ACTIVE → BEACONING on silence)

The core of the loop fix. Track the last data-frame time; when ACTIVE goes silent past `link_lost_timeout`, drop to BEACONING and emit `"lost"` so the next `0x40` re-handshakes via `_handle_beaconing`. Crucially, `0x40` discovery frames do **not** refresh liveness (only real telemetry does), so a sensor that switches from telemetry to `0x40`-spam does time out and get re-handshaked instead of being ignored forever.

**Files:**
- Modify: `tools/sx1302/superlink/bridge/session.py` (`__init__`, `start`, `_dispatch`, `tick`)
- Test: `tests/test_bridge_session.py`

**Interfaces:**
- Consumes: `State`, `DeviceStateEvent`, `self._state`, `self.session_key`, `self.sensor_mac`, `self._pending_bodies`.
- Produces: `DeviceSession(..., link_lost_timeout: float = 60.0)`; instance attr `self._last_data_rx: float`; `tick(now)` may append `DeviceStateEvent(mac, state="lost")` and set `self._state = State.BEACONING`, `self.session_key = None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_bridge_session.py  (add near the reconnect section)
def _active_data_session(link_lost_timeout=60.0):
    from superlink.bridge.session import State
    s = DeviceSession(DeviceRecord(mac=SENSOR_MAC, adopted=True), gw_mac=GW_MAC,
                      pairing_key=DEFAULT_PAIRING_KEY, profiles=ProfileRegistry.load(),
                      link_lost_timeout=link_lost_timeout)
    s.start(now=0.0)
    s._state = State.ACTIVE
    s.session_key = bytes(range(32))
    s.sensor_mac = SENSOR_MAC
    s._adopted = True
    s._last_data_rx = 0.0
    return s

def _data_frame_0x54():
    from superlink.decoder import SuperLinkFrame
    return SuperLinkFrame(mctrl=0xE0, dctrl=0x54, mac=SENSOR_MAC, seq_hi=0x10,
                          seq_lo=0x00, encrypted=b"", direction="UL",
                          frame_type="data", payload=None)

def test_active_drops_to_beaconing_after_link_lost_timeout():
    from superlink.bridge.session import State
    from superlink.bridge.events import DeviceStateEvent
    s = _active_data_session(link_lost_timeout=60.0)
    frames, events = s.tick(now=61.0)            # 61s of silence > 60s timeout
    assert s._state == State.BEACONING
    assert s.session_key is None
    assert any(isinstance(e, DeviceStateEvent) and e.state == "lost" for e in events)

def test_data_frame_refreshes_liveness():
    from superlink.bridge.session import State
    s = _active_data_session(link_lost_timeout=60.0)
    s.feed(_data_frame_0x54(), channel=1, now=50.0)   # telemetry at t=50
    s.tick(now=100.0)                                  # only 50s since data
    assert s._state == State.ACTIVE                    # still healthy

def test_discovery_0x40_does_not_refresh_liveness():
    # A reconnecting sensor sends 0x40s, NOT telemetry. Those must not keep the
    # link "alive" — otherwise an ACTIVE session ignoring 0x40 strands it forever.
    from superlink.bridge.session import State
    s = _active_data_session(link_lost_timeout=60.0)
    s.feed(_craft_discovery_frame(ADOPTED_DISCOVERY_PAYLOAD), channel=1, now=50.0)
    s.tick(now=61.0)                                    # 61s since last DATA
    assert s._state == State.BEACONING                 # timed out despite the 0x40

def test_lost_timeout_preserves_pending_bodies():
    s = _active_data_session(link_lost_timeout=60.0)
    s.queue_body(b"\x08\x01")                          # a LOCATE-ish body
    s.tick(now=61.0)
    assert s._pending_bodies == [b"\x08\x01"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_session.py -k "liveness or link_lost or does_not_refresh" -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'link_lost_timeout'`

- [ ] **Step 3: Write minimal implementation**

In `DeviceSession.__init__` signature add the param:

```python
                 beacon_interval: float = 240.0,
                 link_lost_timeout: float = 60.0,
```

In `__init__` body (near `self.beacon_interval = beacon_interval`):

```python
        self.link_lost_timeout = link_lost_timeout
        # Wall-clock of the last DATA (0x54/0x44) frame — the link-liveness
        # heartbeat. 0x40 discoveries deliberately do NOT refresh this.
        self._last_data_rx = 0.0
```

In `start()` (after `self._last_beacon_time = now`):

```python
        self._last_data_rx = now
```

In `_dispatch`, immediately after the `if frame is None: return None, [], []` guard, add liveness tracking and post-dispatch ACTIVE-entry grace:

```python
        if frame.dctrl in (0x54, 0x44):
            self._last_data_rx = now
        was_active = self._state == State.ACTIVE
        result = (self._handle_active(frame, channel) if self._state == State.ACTIVE
                  else self._handle_beaconing(frame, channel)
                  if self._state == State.BEACONING else (None, [], []))
        if not was_active and self._state == State.ACTIVE:
            # Just (re)entered ACTIVE via handshake — grant a grace period so the
            # timeout does not fire before telemetry resumes.
            self._last_data_rx = now
        return result
```

(Replace the existing `if self._state == State.ACTIVE: ... elif ...` dispatch body with the block above; keep the trailing `log.debug(... no handler ...)` behavior by returning `(None, [], [])` for other states as shown.)

In `tick(now)`, before the final `return frames, events`, add:

```python
        if (self._state == State.ACTIVE
                and (now - self._last_data_rx) >= self.link_lost_timeout):
            log.info("link lost: no telemetry for %.0fs — dropping to BEACONING "
                     "(will re-handshake on next discovery)",
                     now - self._last_data_rx)
            self._state = State.BEACONING
            self.session_key = None
            if self.sensor_mac:
                events.append(DeviceStateEvent(mac=self.sensor_mac, state="lost"))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_session.py -v`
Expected: PASS (new + existing session tests). Then full suite:
Run: `source .venv/bin/activate && python -m pytest tests/ -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/session.py tests/test_bridge_session.py
git commit -m "feat(bridge): telemetry-liveness timeout drops ACTIVE->BEACONING on silence"
```

---

### Task 3: Loop-guard / backoff for never-settling reconnects

If re-handshakes keep completing but the sensor never resumes telemetry (the pathological loop), stop answering `0x40`s for a cooldown instead of re-handshaking every `link_lost_timeout`.

**Files:**
- Modify: `tools/sx1302/superlink/bridge/session.py` (`__init__`, `tick`, `_handle_beaconing` `0x40` branch)
- Test: `tests/test_bridge_session.py`

**Interfaces:**
- Consumes: the `"lost"` transition in `tick` (Task 2).
- Produces: `DeviceSession(..., reconnect_storm_k: int = 3, reconnect_storm_window: float = 30.0, reconnect_backoff: float = 60.0)`; attrs `self._lost_times: list[float]`, `self._backoff_until: float`. During backoff, a `0x40` in BEACONING yields no ConnRsp.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_session.py  (add)
def test_reconnect_storm_triggers_backoff():
    from superlink.bridge.session import State
    from superlink.bridge.core import OutgoingFrame
    s = _active_data_session(link_lost_timeout=10.0)
    # Simulate 3 lost transitions in the window by ticking past timeout repeatedly,
    # never feeding telemetry, re-arming ACTIVE between each (as a re-handshake would).
    for t in (11.0, 22.0, 33.0):
        s._state = State.ACTIVE
        s.session_key = bytes(range(32))
        s._last_data_rx = t - 11.0
        s.tick(now=t)                       # -> lost (3rd trips the storm guard)
    # Now a fresh discovery in BEACONING must be ignored (backing off).
    frames, _ = s.feed(_craft_discovery_frame(ADOPTED_DISCOVERY_PAYLOAD),
                       channel=1, now=34.0)
    assert not any(isinstance(f, OutgoingFrame) for f in frames), \
        "during backoff a 0x40 must not be answered with a ConnRsp"

def test_backoff_clears_after_cooldown():
    from superlink.bridge.session import State
    from superlink.bridge.core import OutgoingFrame
    s = _active_data_session(link_lost_timeout=10.0)
    for t in (11.0, 22.0, 33.0):
        s._state = State.ACTIVE
        s.session_key = bytes(range(32))
        s._last_data_rx = t - 11.0
        s.tick(now=t)
    # After the 60s cooldown, discovery is answered again.
    frames, _ = s.feed(_craft_discovery_frame(ADOPTED_DISCOVERY_PAYLOAD),
                       channel=1, now=34.0 + 61.0)
    assert any(isinstance(f, OutgoingFrame) for f in frames)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_session.py -k "storm or backoff" -v`
Expected: FAIL — `TypeError` (unknown kwargs) or the ConnRsp is still emitted.

- [ ] **Step 3: Write minimal implementation**

`__init__` signature add:

```python
                 reconnect_storm_k: int = 3,
                 reconnect_storm_window: float = 30.0,
                 reconnect_backoff: float = 60.0,
```

`__init__` body:

```python
        self.reconnect_storm_k = reconnect_storm_k
        self.reconnect_storm_window = reconnect_storm_window
        self.reconnect_backoff = reconnect_backoff
        self._lost_times: list[float] = []
        self._backoff_until = 0.0
```

In `tick`, inside the link-lost block from Task 2 (right after appending the `"lost"` event), add storm accounting:

```python
            self._lost_times = [t for t in self._lost_times
                                if now - t <= self.reconnect_storm_window]
            self._lost_times.append(now)
            if len(self._lost_times) >= self.reconnect_storm_k:
                self._backoff_until = now + self.reconnect_backoff
                self._lost_times.clear()
                log.warning("reconnect storm (%d lost in %.0fs) — backing off %.0fs",
                            self.reconnect_storm_k, self.reconnect_storm_window,
                            self.reconnect_backoff)
```

In `_handle_beaconing`, at the very top of the `if frame.dctrl == 0x40:` branch (before decrypting), add:

```python
            # feed() passes now via _dispatch's liveness update; reuse _last_data_rx
            # only for telemetry — carry a separate 'now' for backoff via the frame's
            # arrival. _handle_beaconing has no `now`, so gate on _backoff_until set
            # by tick() and cleared here once a real handshake is allowed.
            if self._backoff_until and self._last_beacon_time < self._backoff_until \
                    and self._backoff_until > 0:
                # Backing off: swallow the discovery (no ConnRsp) until cooldown.
                # tick() advances _last_beacon_time via beacons; when it passes
                # _backoff_until the guard opens.
                return frame if False else (None, [], events)
```

NOTE to implementer: `_handle_beaconing` lacks a `now` argument, so backoff timing here keys off `_backoff_until` vs a clock the beaconing path already sees. If threading `now` into `_handle_beaconing` is cleaner in the actual code, do that instead (update `_dispatch` and the `gateway.py` adapter call sites) and compare `now < self._backoff_until` directly. Prefer the explicit-`now` version if the adapter change is small; the test asserts behavior, not mechanism.

- [ ] **Step 4: Run tests to verify they pass**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_session.py -v && python -m pytest tests/ -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/session.py tests/test_bridge_session.py
git commit -m "feat(bridge): back off on reconnect storms instead of re-handshaking forever"
```

---

### Task 4: Auto-re-adopt when the sensor was factory-reset

Observed live: an adopted session that receives an **unadopted-form** `0x40` (networkId all-zero) is a factory-reset sensor. Today those are silently ignored (stale store record). Detect it, clear the session's adoption, and emit an event so the runtime clears the persisted record and the fresh pair proceeds.

**Files:**
- Modify: `tools/sx1302/superlink/bridge/session.py` (`_handle_active` `0x40` branch)
- Modify: `tools/sx1302/superlink/bridge/runtime.py` (`_on_event`)
- Test: `tests/test_bridge_session.py`, `tests/test_bridge_runtime_events.py`

**Interfaces:**
- Consumes: `is_discovery_ad`, decrypted `0x40` payload, `self._adopted`.
- Produces: on an unadopted-form `0x40` while adopted, the session sets `self._adopted = False`, clears derived keys, drops to BEACONING, and emits `DeviceStateEvent(mac, state="discovered")`. Runtime `_on_event` on `state == "discovered"` for a known store record deletes that record.

- [ ] **Step 1: Write the failing test (session)**

```python
# tests/test_bridge_session.py  (add)
UNADOPTED_DISCOVERY_PAYLOAD = bytes.fromhex("02ae9406000000000002")  # zero networkId

def test_unadopted_discovery_on_adopted_session_triggers_readopt():
    from superlink.bridge.session import State
    from superlink.bridge.events import DeviceStateEvent
    s = _active_data_session()
    s._derived_addDevice_key = bytes(range(32))
    frames, events = s.feed(_craft_discovery_frame(UNADOPTED_DISCOVERY_PAYLOAD),
                            channel=1, now=5.0)
    assert s._adopted is False, "factory-reset sensor must clear adoption"
    assert s._state == State.BEACONING
    assert any(isinstance(e, DeviceStateEvent) and e.state == "discovered"
               for e in events)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_session.py::test_unadopted_discovery_on_adopted_session_triggers_readopt -v`
Expected: FAIL (`_adopted` stays True; no `"discovered"` event).

- [ ] **Step 3: Write minimal implementation (session)**

In `_handle_active`, the `0x40` branch currently decrypts with `pairing_key`. Replace that branch body with reset-detection:

```python
        if frame.dctrl == 0x40:
            frame = decrypt_frame(frame, self.pairing_key,
                                  ul_counter_offset=frame.seq_hi)
            unadopted = (is_discovery_ad(frame.payload)
                         and frame.payload[4:8] == b"\x00\x00\x00\x00")
            if self._adopted and unadopted:
                log.info("factory-reset detected (unadopted 0x40 while adopted) "
                         "from %s — clearing adoption to re-pair", format_mac(frame.mac))
                self._adopted = False
                self._adopt_pending = False
                self._derived_addDevice_key = None
                self._derived_addDevice_fb_key = None
                self._kdf_context = self.pairing_key
                self._kdf_context_explicit = False
                self._transport_key = self.pairing_key
                self.session_key = None
                self._state = State.BEACONING
                mac = frame.mac
                return frame, [], [DeviceStateEvent(mac=mac, state="discovered")]
            # Otherwise: an ordinary reconnect 0x40 — leave it to the liveness
            # timeout (Task 2) to drop us to BEACONING; ignore here.
            return frame, [], events
        elif frame.dctrl in (0x53, 0x43):
```

- [ ] **Step 4: Run session test to verify it passes**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_session.py::test_unadopted_discovery_on_adopted_session_triggers_readopt -v`
Expected: PASS

- [ ] **Step 5: Write the failing test (runtime deletes the record)**

```python
# tests/test_bridge_runtime_events.py  (add)
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.store import InMemoryDeviceStore, DeviceRecord
from superlink.bridge.events import DeviceStateEvent
from tests.support.fake_hal import FakeHal

MAC = bytes.fromhex("9041B22E9A53")

def test_discovered_event_deletes_stale_store_record():
    store = InMemoryDeviceStore()
    store.save(DeviceRecord(mac=MAC, adopted=True))
    cfg = RuntimeConfig(gw_mac=bytes.fromhex("010203040506"),
                        pairing_key=DEFAULT_PAIRING_KEY, adopt=ADOPT_ALL)
    rt = BridgeRuntime(cfg, FakeHal(), store=store)
    rt._on_event(DeviceStateEvent(mac=MAC, state="discovered"))
    assert all(r.mac != MAC for r in store.load_all()), \
        "a re-discovered (factory-reset) device's stale record must be removed"
```

- [ ] **Step 6: Run to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_runtime_events.py::test_discovered_event_deletes_stale_store_record -v`
Expected: FAIL — record still present (and possibly `AttributeError` if `InMemoryDeviceStore` lacks `delete`; if so, add a `delete(mac)` method to both stores in `store.py` as part of this step, mirroring `save`).

- [ ] **Step 7: Write minimal implementation (runtime + store)**

If `store.py` lacks `delete`, add to both `JsonDeviceStore` and `InMemoryDeviceStore`:

```python
    def delete(self, mac: bytes) -> None:
        self._records.pop(mac, None)     # InMemory
```
```python
    def delete(self, mac: bytes) -> None:  # JsonDeviceStore
        data = self._load_raw()
        if data.pop(mac.hex(), None) is not None:
            self._write_raw(data)
```

(Match the file's existing load/write helpers; if names differ, adapt.)

In `BridgeRuntime._on_event`, extend the `DeviceStateEvent` handling:

```python
        elif isinstance(event, DeviceStateEvent) and event.state == "discovered":
            # A previously-adopted device re-advertised as unadopted (factory
            # reset). Drop the stale record so the fresh pair re-adopts cleanly.
            if any(r.mac == event.mac for r in self.store.load_all()):
                self.store.delete(event.mac)
                log.info("removed stale record for re-discovered %s", event.mac.hex())
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `source .venv/bin/activate && python -m pytest tests/ -q`
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add tools/sx1302/superlink/bridge/session.py tools/sx1302/superlink/bridge/runtime.py tools/sx1302/superlink/bridge/store.py tests/test_bridge_session.py tests/test_bridge_runtime_events.py
git commit -m "feat(bridge): auto-re-adopt a factory-reset sensor (unadopted 0x40 while adopted)"
```

---

### Task 5: Config knobs + live validation on the bench

Expose the tunables via `RuntimeConfig` and pass them into sessions, then validate against the real sensor.

**Files:**
- Modify: `tools/sx1302/superlink/bridge/config.py` (`RuntimeConfig` fields + `load`)
- Modify: `tools/sx1302/superlink/bridge/runtime.py` (`_session_factory` passes the knobs)
- Modify: `tools/sx1302/superlink_bridge.yaml.example` (document the knobs)
- Test: `tests/test_bridge_config.py`

**Interfaces:**
- Produces: `RuntimeConfig.link_lost_timeout: float = 60.0` (from yaml `link_lost_timeout`); `_session_factory` passes `link_lost_timeout=self.config.link_lost_timeout` to `DeviceSession`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_config.py  (add)
def test_link_lost_timeout_default_and_override(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_ALL))
    assert c.link_lost_timeout == 60.0
    c2 = RuntimeConfig.load(_write(
        tmp_path, 'gw_mac: "010203040506"\nadopt: all\nlink_lost_timeout: 45\n'))
    assert c2.link_lost_timeout == 45.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `source .venv/bin/activate && python -m pytest tests/test_bridge_config.py -k link_lost -v`
Expected: FAIL — `AttributeError: ... 'link_lost_timeout'`

- [ ] **Step 3: Write minimal implementation**

`config.py` — add field to `RuntimeConfig`:

```python
    link_lost_timeout: float = 60.0
```

In `RuntimeConfig.load`'s `return cls(...)` add:

```python
            link_lost_timeout=float(doc.get("link_lost_timeout", 60.0)),
```

`runtime.py` `_session_factory` — pass it:

```python
        s = DeviceSession(record, gw_mac=self.config.gw_mac,
                          pairing_key=self.config.pairing_key,
                          profiles=self.profiles,
                          link_lost_timeout=self.config.link_lost_timeout)
```

`superlink_bridge.yaml.example` — add near `log:`:

```yaml
# Seconds of telemetry silence before the bridge treats the link as lost and
# re-handshakes on the sensor's next discovery. ~a few missed reports.
link_lost_timeout: 60
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source .venv/bin/activate && python -m pytest tests/ -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/config.py tools/sx1302/superlink/bridge/runtime.py tools/sx1302/superlink_bridge.yaml.example tests/test_bridge_config.py
git commit -m "feat(bridge): configurable link_lost_timeout"
```

- [ ] **Step 6: Live validation (bench)**

Deploy and validate against sensor `9041b22e9a53` (see memory `bridge_reconnect_loop_negative` for bench ops):
1. `rsync` the package to the Pi; restart `superlink-bridged`.
2. Confirm steady telemetry (green), then observe a natural reconnect: the log should show `link lost: no telemetry ...` → BEACONING → a single clean re-handshake → telemetry resumes. **No** rapid DISCOVERY storm, **no** red-LED loop.
3. Factory-reset the sensor (physical): the log should show `factory-reset detected ...` → `removed stale record ...` → fresh ADOPT → COMMIT → telemetry, with **no** manual store clearing.
4. Verify LED settles to blue/paired and holds (per `feedback_verify_before_success` — LED + telemetry, not frames alone).

---

## Self-Review

**Spec coverage:** Track B piece "explicit connection state + timers" → Tasks 1–2. "graceful re-handshake (debounce/backoff)" → Tasks 2 (timeout rate-limits, replacing per-0x40 debounce) + 3 (backoff). "factory-reset auto-re-adopt" (discovered during kickoff) → Task 4. Config/validation → Task 5. Track A (beacon + command-window RE) is intentionally out of scope (separate bench effort). No gaps for Track B.

**Placeholder scan:** No TBD/TODO. Task 3's `_handle_beaconing` backoff has an explicit implementer note offering a cleaner `now`-threading alternative — this is guidance, not a placeholder; the test asserts behavior either way.

**Type consistency:** `link_lost_timeout` (float) consistent across session `__init__`, config, factory. `_last_data_rx` set in `__init__`/`start`/`_dispatch`, read in `tick`. `DeviceStateEvent(mac=, state="lost"|"discovered")` matches existing usage and `DEVICE_STATES`. `tick(now) -> (frames, events)` unchanged signature. `store.delete(mac)` added to both stores, called in `_on_event`.
