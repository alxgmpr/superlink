# Factory Reset / Unpair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the SuperLink `FACTORY_RESET` command as a Home Assistant button, and have the bridge forget the device — record, session, and HA entities — once the sensor confirms the reset with a tag-matched status reply.

**Architecture:** The wire path (`encode_factory_reset` → `FactoryReset` action → `mapping.action_to_body`) already exists and is hardware-verified; this plan adds only the confirmation and bookkeeping around it. `BridgeCore` remembers the messageTag it stamped on a `FactoryReset`, watches for the sensor's `REQUEST_STATUS_RESPONSE` (msgId 1) echoing that tag with status 0, and only then deletes the device and emits `DeviceRemoved`. `MqttBridge` reacts to `DeviceRemoved` by retracting every retained topic it published for that device.

**Tech Stack:** Python 3, pytest, paho-mqtt (via `FakeMqttClient` double in tests). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-05-factory-reset-unpair-design.md`

## Global Constraints

- All bridge code lives in `tools/sx1302/superlink/`. `tests/conftest.py` adds `tools/sx1302` to `sys.path`, so tests import as `superlink.bridge.*`.
- Run tests from the repo root with the venv active: `source .venv/bin/activate && pytest tests/ -v`.
- **Accepted-red baseline:** 2 tests in `tests/test_gateway.py` fail on `main` (the ConnChallenge pubkey-offset `[3:35]` vs `[13:45]` question). Do NOT fix them as part of this work. Every *other* test must pass.
- The sensor rejects a tag-0 command body — a tag-0 `FACTORY_RESET` (`0700`) is silently ignored, no ACK and no reset (verified on hardware 2026-07-25). `BridgeCore._cmd_tag` already guarantees 1..255; do not change it.
- Teardown is **confirm-only**: no fallback timeout. A tag mismatch or a non-zero status code must leave the device record intact.
- Ground-truth reference capture: `captures/live/bridge_adopt_fresh_pass2_DECODED.txt`. The real controller sends `0735`, receives `013500`, then issues `removeDevice`.
- Commit after each task with the `feat(bridge):` / `refactor(bridge):` prefix style used in this repo.

---

### Task 1: Typed `CommandStatus` event for REQUEST_STATUS_RESPONSE

The sensor's reply to a command is msgId 1, carrying the echoed messageTag and a status code. Today it falls through to the generic `RawMessageEvent`, which discards the tag (`body[2:]`) — so nothing downstream can correlate a reply to the command that caused it. This task makes it a typed event.

**Files:**
- Modify: `tools/sx1302/superlink/bridge/events.py` (add dataclass after `RawMessageEvent`, ~line 76)
- Modify: `tools/sx1302/superlink/bridge/mapping.py` (import at line 4-8; new branch before the `RawMessageEvent` fallthrough at line 58)
- Modify: `tools/sx1302/command_probe.py:111` (consumer of the old shape)
- Test: `tests/test_bridge_mapping.py`

**Interfaces:**
- Consumes: `appmsg.decode_message`, which already returns `{"messageId", "messageTag", "statusCode"}` for msgId 1 (`appmsg.py:153-156`).
- Produces: `superlink.bridge.events.CommandStatus(mac: bytes, message_tag: int, status_code: int)` — Task 2 consumes this.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_bridge_mapping.py`:

```python
def test_status_response_becomes_command_status(reg):
    """msgId 1 is the sensor's reply to a command, echoing that command's
    messageTag. Ground truth: body `013500` closed the FACTORY_RESET tagged
    0x35 in captures/live/bridge_adopt_fresh_pass2_DECODED.txt."""
    from superlink.bridge.events import CommandStatus
    evs = events_from_app_message(MAC, bytes.fromhex("013500"), reg)
    assert len(evs) == 1
    ev = evs[0]
    assert isinstance(ev, CommandStatus)
    assert ev.mac == MAC
    assert ev.message_tag == 0x35
    assert ev.status_code == 0


def test_status_response_reports_nonzero_status(reg):
    from superlink.bridge.events import CommandStatus
    evs = events_from_app_message(MAC, bytes.fromhex("01420b"), reg)
    assert isinstance(evs[0], CommandStatus)
    assert evs[0].message_tag == 0x42 and evs[0].status_code == 0x0b
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_bridge_mapping.py -k command_status -v`
Expected: FAIL — `ImportError: cannot import name 'CommandStatus'`

- [ ] **Step 3: Add the event dataclass**

In `tools/sx1302/superlink/bridge/events.py`, after the `RawMessageEvent` dataclass:

```python
@dataclass(frozen=True)
class CommandStatus(Event):
    """REQUEST_STATUS_RESPONSE (msgId 1): the sensor's reply to a command,
    echoing that command's messageTag. statusCode 0 = success.

    The reply arrives in a *later* window than the command it answers (a
    FACTORY_RESET goes out on 0x74; its status comes back on a subsequent
    0x54), so consumers must correlate on message_tag, not on ordering."""
    mac: bytes
    message_tag: int
    status_code: int
```

- [ ] **Step 4: Emit it from the mapper**

In `tools/sx1302/superlink/bridge/mapping.py`, add `CommandStatus` to the import from `.events` (line 4-8), then insert this branch immediately before the final `return [RawMessageEvent(...)]` at line 58:

```python
    if msg_id == appmsg.MessageId.REQUEST_STATUS_RESPONSE:
        return [CommandStatus(mac=mac, message_tag=msg["messageTag"],
                              status_code=msg["statusCode"])]
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pytest tests/test_bridge_mapping.py -v`
Expected: PASS. The pre-existing `test_unknown_message_is_raw` uses msgId 200, so it is unaffected by this change.

- [ ] **Step 6: Update the `command_probe.py` consumer**

`tools/sx1302/command_probe.py` reads msgId 1 in two places. Add `CommandStatus` to the `from superlink.bridge.events import (...)` list at line 32, then:

In `describe()`, add a branch immediately **before** the `RawMessageEvent` branch at line 96 (msgId 1 is no longer a `RawMessageEvent`, so without this the probe prints nothing for a status reply):

```python
    if isinstance(ev, CommandStatus):
        return f"STATUS tag=0x{ev.message_tag:02x} status={ev.status_code}"
```

In `expected_response()` at line 111, replace:

```python
    if isinstance(ev, RawMessageEvent) and ev.message_id == 1:
```

with:

```python
    if isinstance(ev, CommandStatus):
```

Leave the `RawMessageEvent` branch at line 96 and the ping check at line 109 (msgId 5) alone — both still apply to other message ids.

- [ ] **Step 7: Verify nothing else regressed**

Run: `pytest tests/ -v`
Expected: PASS except the 2 known-red `tests/test_gateway.py` ConnChallenge tests.

- [ ] **Step 8: Commit**

```bash
git add tools/sx1302/superlink/bridge/events.py tools/sx1302/superlink/bridge/mapping.py tools/sx1302/command_probe.py tests/test_bridge_mapping.py
git commit -m "feat(bridge): decode REQUEST_STATUS_RESPONSE into a typed CommandStatus event"
```

---

### Task 2: Confirm-gated device teardown in BridgeCore

`BridgeCore` stamps each command with a running tag. This task makes it remember the tag it used for a `FactoryReset`, and tear the device down when the matching success status arrives.

**Files:**
- Modify: `tools/sx1302/superlink/bridge/events.py` (add `DeviceRemoved` after `CommandStatus`)
- Modify: `tools/sx1302/superlink/bridge/core.py` (`__init__` ~line 54, `feed` ~line 89, `tick` ~line 112, `submit` ~line 121; new `_intercept` and `_remove_device`)
- Test: `tests/test_bridge_core.py`

**Interfaces:**
- Consumes: `CommandStatus(mac, message_tag, status_code)` from Task 1.
- Produces: `superlink.bridge.events.DeviceRemoved(mac: bytes, reason: str)` — Task 4 consumes this. Reason is the string `"factory_reset"`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_bridge_core.py`. Note `FakeSession.feed` (line 22) returns a fixed `PropertyEvent`; these tests need a session that emits a caller-chosen event, so they use a small local subclass.

```python
# --- factory reset / unpair teardown ---

class StatusSession(FakeSession):
    """FakeSession whose feed() emits whatever events are put in `to_emit`."""
    def __init__(self, record):
        super().__init__(record)
        self.to_emit = []
    def feed(self, frame, channel, now, rssi=None, snr=None):
        evs, self.to_emit = self.to_emit, []
        return [], evs
    def tick(self, now):
        evs, self.to_emit = self.to_emit, []
        return [], evs


def _adopted_core():
    """Core with MAC already adopted and a StatusSession attached."""
    store = InMemoryDeviceStore()
    store.save(DeviceRecord(mac=MAC, adopted=True))
    core = BridgeCore(store, ProfileRegistry.load(),
                      session_factory=StatusSession)
    return core, store, core._sessions[MAC]


def test_factory_reset_confirmed_removes_device():
    """The real controller waits for the tag-matched status before issuing
    removeDevice (captures/live/bridge_adopt_fresh_pass2_DECODED.txt)."""
    from superlink.bridge.events import FactoryReset, CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag, status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC not in core._sessions
    assert store.load_all() == []
    removed = [e for e in seen if isinstance(e, DeviceRemoved)]
    assert len(removed) == 1
    assert removed[0].mac == MAC and removed[0].reason == "factory_reset"


def test_factory_reset_wrong_tag_does_not_remove():
    """A status closing some other command must not unpair the device."""
    from superlink.bridge.events import FactoryReset, CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag ^ 0xFF,
                                  status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC in core._sessions
    assert len(store.load_all()) == 1
    assert not any(isinstance(e, DeviceRemoved) for e in seen)


def test_factory_reset_nonzero_status_does_not_remove():
    """A failed reset leaves the record alone: a stale record is recoverable,
    a wrongly-deleted one needs a physical re-pair."""
    from superlink.bridge.events import FactoryReset, CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag, status_code=3)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC in core._sessions
    assert len(store.load_all()) == 1
    assert not any(isinstance(e, DeviceRemoved) for e in seen)


def test_status_without_pending_reset_does_not_remove():
    """Statuses close every command (locate, reboot, property_set). Only one
    with a pending FACTORY_RESET may tear the device down."""
    from superlink.bridge.events import CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=1, status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    assert MAC in core._sessions
    assert not any(isinstance(e, DeviceRemoved) for e in seen)


def test_factory_reset_confirmed_during_tick_does_not_raise():
    """tick() iterates the session dict; teardown mutates it mid-loop unless
    the loop walks a snapshot."""
    from superlink.bridge.events import FactoryReset, CommandStatus, DeviceRemoved
    core, store, sess = _adopted_core()
    seen = []
    core.subscribe(seen.append)
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag, status_code=0)]
    core.tick(now=5.0)
    assert MAC not in core._sessions
    assert any(isinstance(e, DeviceRemoved) for e in seen)


def test_removed_device_is_rediscoverable():
    """After a reset the sensor beacons again as unadopted; with the record
    gone the bridge must announce it as a fresh discovery, not route it to a
    dead session."""
    from superlink.bridge.events import FactoryReset, CommandStatus
    core, store, sess = _adopted_core()
    core.submit(FactoryReset(mac=MAC))
    tag = sess.queued[0][1]
    sess.to_emit = [CommandStatus(mac=MAC, message_tag=tag, status_code=0)]
    core.feed(UNKNOWN_FRAME, channel=1, now=5.0)
    seen = []
    core.subscribe(seen.append)
    core.feed(UNKNOWN_FRAME, channel=1, now=6.0)
    assert any(isinstance(e, DeviceDiscovered) for e in seen)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_bridge_core.py -k factory_reset -v`
Expected: FAIL — `ImportError: cannot import name 'DeviceRemoved'`

- [ ] **Step 3: Add the `DeviceRemoved` event**

In `tools/sx1302/superlink/bridge/events.py`, after `CommandStatus`:

```python
@dataclass(frozen=True)
class DeviceRemoved(Event):
    """The bridge has forgotten a device: record deleted, session torn down.
    Consumers should retract any state they published for it."""
    mac: bytes
    reason: str          # "factory_reset"
```

- [ ] **Step 4: Track the pending reset tag**

In `tools/sx1302/superlink/bridge/core.py`:

Extend the import from `.events` (line 7-9) to include `CommandStatus`, `DeviceRemoved`, and `FactoryReset`.

In `__init__`, after `self._cmd_tag = 0` (line 54):

```python
        # mac -> messageTag of a FACTORY_RESET awaiting its status reply. The
        # sensor answers in a later window, so the teardown is event-driven:
        # only a tag-matched status with code 0 removes the device.
        self._pending_reset: dict[bytes, int] = {}
```

In `submit()`, after the `session.queue_body(...)` call (line 130-131):

```python
        if isinstance(action, FactoryReset):
            self._pending_reset[action.mac] = self._cmd_tag
```

- [ ] **Step 5: Add the interception and teardown**

Still in `core.py`, add these two methods (place them after `_adopt`):

```python
    def _intercept(self, events) -> None:
        """Act on events before they reach subscribers.

        A FACTORY_RESET is confirmed by a REQUEST_STATUS_RESPONSE echoing the
        command's messageTag with status 0 — the same signal the real
        controller waits for before issuing removeDevice. Anything else (wrong
        tag, non-zero status) leaves the record alone: a stale record is
        recoverable, a wrongly-deleted one needs a physical re-pair.
        """
        for ev in events:
            if not isinstance(ev, CommandStatus):
                continue
            pending = self._pending_reset.get(ev.mac)
            if pending is None or ev.message_tag != pending:
                continue
            if ev.status_code != 0:
                log.warning("factory reset on %s failed: status=%d "
                            "(keeping device record)",
                            ev.mac.hex(), ev.status_code)
                self._pending_reset.pop(ev.mac, None)
                continue
            self._remove_device(ev.mac, "factory_reset")

    def _remove_device(self, mac: bytes, reason: str) -> None:
        """Forget a device entirely: session, start-state, and stored record."""
        self._sessions.pop(mac, None)
        self._started.discard(mac)
        self._discovered.pop(mac, None)
        self._pending_reset.pop(mac, None)
        self.store.delete(mac)
        log.info("removed device %s (%s)", mac.hex(), reason)
        self._emit([DeviceRemoved(mac=mac, reason=reason)])
```

`core.py` has no logger yet. Add it below the imports, matching the naming used elsewhere in the package (`control.py:37` uses `logging.getLogger("superlink.control")`):

```python
import logging

log = logging.getLogger("superlink.core")
```

- [ ] **Step 6: Call `_intercept` on both event paths**

In `feed()`, replace line 89-91:

```python
            frames, events = session.feed(frame, channel, now, rssi=rssi, snr=snr)
            self._intercept(events)
            self._emit(events)
            return list(frames)
```

In `tick()`, replace the loop body (lines 113-119) — note the snapshot, since `_remove_device` mutates `self._sessions`:

```python
        out: list[OutgoingFrame] = []
        for mac, session in list(self._sessions.items()):
            self._ensure_started(mac, session, now)
            frames, events = session.tick(now)
            out.extend(frames)
            self._intercept(events)
            self._emit(events)
        return out
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `pytest tests/test_bridge_core.py -v`
Expected: PASS

- [ ] **Step 8: Verify nothing else regressed**

Run: `pytest tests/ -v`
Expected: PASS except the 2 known-red `tests/test_gateway.py` tests.

- [ ] **Step 9: Commit**

```bash
git add tools/sx1302/superlink/bridge/events.py tools/sx1302/superlink/bridge/core.py tests/test_bridge_core.py
git commit -m "feat(bridge): forget a device once its FACTORY_RESET is confirmed"
```

---

### Task 3: Factory reset button in Home Assistant

Adds the button entity and wires its press to the `FactoryReset` action. Purely additive — the existing `_publish_buttons` loop picks up any new entry in `COMMAND_BUTTONS`.

**Files:**
- Modify: `tools/sx1302/superlink/bridge/entities.py:27-32` (`COMMAND_BUTTONS`)
- Modify: `tools/sx1302/superlink/bridge/mqtt.py:19-27` (`_BUTTON_ACTIONS`), line 12-16 (import)
- Test: `tests/test_bridge_mqtt.py`

**Interfaces:**
- Consumes: `FactoryReset(mac)` from `superlink.bridge.events` (already exists, `events.py:120`).
- Produces: MQTT command topic `superlink/<machex>/factory_reset/press`, discovery at `homeassistant/button/<machex>_factory_reset/config`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_bridge_mqtt.py`:

```python
# --- factory reset / unpair button ---

def test_factory_reset_button_submits_action():
    from superlink.bridge.events import FactoryReset
    rt, client, bridge = _bridge()
    got = []
    rt.submit_action = lambda a: got.append(a)
    bridge.start()
    bridge._on_message(f"superlink/{MH}/factory_reset/press", "PRESS")
    assert len(got) == 1 and isinstance(got[0], FactoryReset)
    assert got[0].mac == MAC


def test_factory_reset_button_discovery_published():
    from superlink.bridge.events import DeviceStateEvent
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    cfg = client.find(f"homeassistant/button/{MH}_factory_reset/config")
    assert cfg is not None
    payload = json.loads(cfg)
    assert payload["command_topic"] == f"superlink/{MH}/factory_reset/press"
    assert payload["name"] == "Factory reset"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_bridge_mqtt.py -k factory_reset -v`
Expected: FAIL — the press is logged as `unknown button 'factory_reset'` and no action is submitted; the discovery topic is `None`.

- [ ] **Step 3: Register the button**

In `tools/sx1302/superlink/bridge/entities.py`, add to `COMMAND_BUTTONS`:

```python
    "factory_reset": {"name": "Factory reset", "icon": "mdi:link-off"},
```

In `tools/sx1302/superlink/bridge/mqtt.py`, add `FactoryReset` to the `.events` import (line 12-16) and add to `_BUTTON_ACTIONS`:

```python
    # Unpairs the sensor. The bridge forgets the device once the sensor
    # confirms with a tag-matched status reply (BridgeCore._intercept).
    "factory_reset": lambda mac: FactoryReset(mac=mac),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_bridge_mqtt.py tests/test_bridge_entities.py -v`
Expected: PASS. `test_bridge_entities.py` has no exact-set assertion on `COMMAND_BUTTONS`, so adding an entry does not break it.

- [ ] **Step 5: Commit**

```bash
git add tools/sx1302/superlink/bridge/entities.py tools/sx1302/superlink/bridge/mqtt.py tests/test_bridge_mqtt.py
git commit -m "feat(bridge): expose factory reset as a Home Assistant button"
```

---

### Task 4: Retract HA entities when a device is removed

Without this, a reset sensor leaves retained discovery configs on the broker and its entities linger in HA forever. `MqttBridge` publishes retained topics from five places; this task routes them through one helper that records what was published per device, so retraction is exact rather than reconstructed.

**Files:**
- Modify: `tools/sx1302/superlink/bridge/mqtt.py` (`__init__` ~line 39-41; `on_event` ~line 73-90; `_publish_buttons`, `_publish_link_signal`, `_publish_button_press`, `_publish_property`)
- Test: `tests/test_bridge_mqtt.py`

**Interfaces:**
- Consumes: `DeviceRemoved(mac, reason)` from Task 2.
- Produces: nothing consumed downstream.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_bridge_mqtt.py`:

```python
# --- entity retraction on device removal ---

def _retracted(client, topic):
    """True if the LAST publish to `topic` was an empty retained payload."""
    for t, p, retain in reversed(client.published):
        if t == topic:
            return p == "" and retain
    return False


def test_device_removed_retracts_discovery_and_state():
    from superlink.bridge.events import DeviceStateEvent, DeviceRemoved
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    bridge.on_event(PropertyEvent(mac=MAC, property_id=3, name="BATTERY",
                                  channel=0, raw=b"\x64", value=100, unit="%",
                                  decoded=True))
    assert client.find(f"homeassistant/sensor/{MH}_BATTERY/config") is not None

    bridge.on_event(DeviceRemoved(mac=MAC, reason="factory_reset"))
    assert _retracted(client, f"homeassistant/sensor/{MH}_BATTERY/config")
    assert _retracted(client, f"homeassistant/button/{MH}_locate/config")
    assert _retracted(client, f"homeassistant/button/{MH}_factory_reset/config")
    assert _retracted(client, f"superlink/{MH}/BATTERY")
    assert _retracted(client, f"superlink/{MH}/availability")


def test_device_removed_retracts_discovered_topic():
    from superlink.bridge.events import DeviceRemoved
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(DeviceDiscovered(mac=MAC, channel=1, first_seen=1.0))
    bridge.on_event(DeviceRemoved(mac=MAC, reason="factory_reset"))
    assert _retracted(client, f"superlink/discovered/{MH}")


def test_readopt_after_removal_republishes_discovery():
    """Removal clears the once-only guards, so a device that is re-paired gets
    its discovery configs published again instead of staying invisible."""
    from superlink.bridge.events import DeviceStateEvent, DeviceRemoved
    rt, client, bridge = _bridge()
    bridge.start()
    bridge.on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    bridge.on_event(DeviceRemoved(mac=MAC, reason="factory_reset"))
    bridge.on_event(DeviceStateEvent(mac=MAC, state="adopted"))
    cfg = client.find(f"homeassistant/button/{MH}_locate/config")
    assert cfg is not None and cfg != ""


def test_removal_of_unknown_device_is_a_noop():
    from superlink.bridge.events import DeviceRemoved
    rt, client, bridge = _bridge()
    bridge.start()
    before = len(client.published)
    bridge.on_event(DeviceRemoved(mac=MAC, reason="factory_reset"))
    assert len(client.published) == before
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_bridge_mqtt.py -k "removed or readopt" -v`
Expected: FAIL — `ImportError: cannot import name 'DeviceRemoved'` if Task 2 is not yet merged, otherwise the retraction assertions fail because nothing retracts.

- [ ] **Step 3: Record retained topics per device**

In `tools/sx1302/superlink/bridge/mqtt.py`, add `DeviceRemoved` to the `.events` import, and in `__init__` after `self._buttons_done` (line 40):

```python
        # mac -> every retained topic published for that device (discovery
        # configs and state). Retraction has to clear exactly these, so they
        # are recorded at publish time rather than reconstructed later.
        self._retained: dict[bytes, set[str]] = {}
```

Add the helper method:

```python
    def _pub_retained(self, mac: bytes, topic: str, payload) -> None:
        """Publish a retained, device-scoped topic and remember it so
        _retract_device can clear it later."""
        self._retained.setdefault(mac, set()).add(topic)
        self.client.publish(topic, payload, retain=True)
```

- [ ] **Step 4: Route the device-scoped retained publishes through it**

Replace each of these `self.client.publish(..., retain=True)` calls with `self._pub_retained(mac, ...)`:

- `on_event`, `DeviceDiscovered` branch (line 81-84): topic `f"{self.base}/discovered/{event.mac.hex()}"`, use `event.mac`.
- `on_event`, `DeviceStateEvent` branch (line 89-90): the availability topic, use `event.mac`.
- `_publish_buttons` (line 100): the button config topic, use `mac`.
- `_publish_link_signal` (line 111 and 113-114): both the config topic and the `SIGNAL` state topic, use `ev.mac`.
- `_publish_button_press` (line 125): the config topic only — the press publish at line 127-128 is deliberately not retained, leave it alone.
- `_publish_property` (line 138 and 146): both the config topic and the state topic, use `ev.mac`.

- [ ] **Step 5: Handle `DeviceRemoved`**

Add a branch to `on_event`:

```python
        elif isinstance(event, DeviceRemoved):
            self._retract_device(event.mac)
```

and the method:

```python
    def _retract_device(self, mac: bytes) -> None:
        """Clear every retained topic published for a device, so its HA
        entities disappear instead of lingering as stale retained configs."""
        topics = self._retained.pop(mac, set())
        for topic in sorted(topics):
            self.client.publish(topic, "", retain=True)
        # Drop the once-only guards so a later re-adopt republishes discovery.
        self._buttons_done.discard(mac)
        machex = mac.hex()
        for key in [k for k in self._discovery_done
                    if k.startswith(f"{machex}_")]:
            self._discovery_done.discard(key)
        if topics:
            log.info("retracted %d retained topics for %s", len(topics), machex)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pytest tests/test_bridge_mqtt.py -v`
Expected: PASS

- [ ] **Step 7: Verify the whole suite**

Run: `pytest tests/ -v`
Expected: PASS except the 2 known-red `tests/test_gateway.py` tests. `test_bridge_mqtt_wiring.py` and `test_bridge_integration.py` exercise the same publish paths but assert on `client.find(...)` and connection state, not on raw `client.publish` call shapes, so routing through `_pub_retained` does not disturb them.

- [ ] **Step 8: Commit**

```bash
git add tools/sx1302/superlink/bridge/mqtt.py tests/test_bridge_mqtt.py
git commit -m "feat(bridge): retract HA entities when a device is removed"
```

---

### Task 5: Document the unpair flow

**Files:**
- Modify: `docs/protocol/superlink_application_layer.md` (the `REBOOT / FACTORY_RESET / LOCATE / DEVICE_INFO_REQUEST (6-9)` section at line 127)
- Modify: `tools/sx1302/superlink/bridge/control.py:10-23` (the docstring's line grammar block)

- [ ] **Step 1: Document the confirmation exchange**

In `docs/protocol/superlink_application_layer.md`, extend the section at line 127 with the observed exchange and its consequence:

```markdown
`FACTORY_RESET` unpairs the device. The messageTag MUST be non-zero — a `0700`
body is silently ignored (no ACK, no reset; verified on hardware 2026-07-25).

The sensor confirms with a `REQUEST_STATUS_RESPONSE` (msgId 1) echoing the
command's tag, in a **later window** than the command itself:

    DL dctrl=74  body=0735      FACTORY_RESET, tag 0x35
    DL dctrl=54  ...
    UL dctrl=54  body=013500    REQUEST_STATUS_RESPONSE, tag 0x35, status 0

The controller removes the device from its registry only after that status
(`captures/live/bridge_adopt_fresh_pass2_DECODED.txt`, JSON 11 `removeDevice`).
superlink2mqtt mirrors this: `BridgeCore` deletes the record and emits
`DeviceRemoved` on a tag-matched status 0, and does nothing on a mismatch or a
non-zero status. After the reset the sensor beacons again as unadopted and can
be re-paired normally.
```

- [ ] **Step 2: Note the teardown in the control-socket docstring**

In `tools/sx1302/superlink/bridge/control.py`, change the grammar line (line 16) to:

```
    factory_reset                    -> FactoryReset (unpairs; bridge forgets
                                        the device once the sensor confirms)
```

- [ ] **Step 3: Commit**

```bash
git add docs/protocol/superlink_application_layer.md tools/sx1302/superlink/bridge/control.py
git commit -m "docs(protocol): document the FACTORY_RESET confirmation exchange"
```

---

## Hardware verification (after the plan is implemented)

Not a code task — this is the bench check that the feature actually works, and it needs the sensor in hand.

1. Deploy: `cd tools/sx1302 && ./deploy.sh run bridged`
2. Wait for the sensor's link to come up (a button nudge is needed after each deploy-restart).
3. Press the **Factory reset** button in HA, or run:
   ```bash
   python3 -m superlink.bridge.control send factory_reset
   ```
4. Expect, in order: the command lands on the next 0x53 window; a `CommandStatus` with status 0 in the log; `removed device <mac> (factory_reset)`; the device's entities disappear from HA.
5. Confirm on the hardware itself — check the sensor LED and that it starts beaconing as unadopted. Do not call it success from the frame exchange alone.
6. Re-pair to confirm the round trip: the bridge should announce it as a fresh `DeviceDiscovered` and re-adopt cleanly with republished entities.

If the sensor resets without ever sending the status, the bridge keeps a record with dead keys — that is the known gap in the spec. Recovery: delete the entry from the store JSON and restart the daemon.
