# Factory reset / unpair action — design

Date: 2026-08-05
Status: approved, ready for implementation plan

## Goal

Expose the SuperLink `FACTORY_RESET` command as a first-class unpair action:
a Home Assistant button that sends it, and bridge-side bookkeeping that forgets
the device once the sensor confirms the reset.

## What already exists

The wire path is complete and hardware-verified — this design adds no new
protocol work.

| Piece | Location |
| --- | --- |
| `encode_factory_reset()` → `[7, tag]` | `tools/sx1302/superlink/appmsg.py:116` |
| `FactoryReset` action dataclass | `tools/sx1302/superlink/bridge/events.py:120` |
| Action → body dispatch | `tools/sx1302/superlink/bridge/mapping.py:78` |
| `factory_reset` control-socket command | `tools/sx1302/superlink/bridge/control.py:80` |
| Non-zero tag allocation (1..255) | `tools/sx1302/superlink/bridge/core.py:129` |

So `python3 -m superlink.bridge.control send factory_reset` already unpairs a
sensor today. The tag must be non-zero — a tag-0 body (`0700`) is silently
ignored by the sensor (no ACK, no reset; verified on hardware 2026-07-25) — and
`BridgeCore._cmd_tag` already guarantees that.

### Missing

1. `factory_reset` is not in `COMMAND_BUTTONS`, so there is no HA button.
2. Nothing cleans up bridge-side state. After the sensor unpairs, the bridge
   keeps a `DeviceRecord` holding now-dead session keys and keeps trying to
   talk to it, and the HA entities linger.

## Ground truth

From `captures/live/bridge_adopt_fresh_pass2_DECODED.txt` (real controller
unpairing sensor `9041B22E9A53`):

```
DL dctrl=74  body=0735        <- FACTORY_RESET, tag 0x35
UL dctrl=74  body=813a
DL dctrl=54  body=be5e2c
UL dctrl=54  body=013500      <- REQUEST_STATUS_RESPONSE, tag 0x35, status 0
[JSON 11] CTL->BR {"action":"removeDevice", "mac":"9041B22E9A53"}
```

Two facts this design depends on:

- The sensor **does** reply with a `REQUEST_STATUS_RESPONSE` (msgId 1) echoing
  the command's messageTag, with `statusCode` 0.
- That status arrives in a **later 0x54 window**, not inline with the 0x74. The
  teardown is therefore asynchronous and must be event-driven.

The controller removes the device only after that status — which is the
behaviour reproduced here.

After the reset the sensor reappears in discovery with `adopted: false`, so a
deleted record means the bridge re-discovers it as a fresh device and it can be
re-adopted normally. `auto_adopt` is `False` in every current caller
(`gateway.py:519`, `runtime.py:38`), so there is no risk of instantly
re-adopting the sensor that was just unpaired.

## Design

### 1. Two new events — `bridge/events.py`

```python
@dataclass(frozen=True)
class CommandStatus(Event):
    """REQUEST_STATUS_RESPONSE (msgId 1): the sensor's reply to a command,
    echoing that command's messageTag. statusCode 0 = success."""
    mac: bytes
    message_tag: int
    status_code: int


@dataclass(frozen=True)
class DeviceRemoved(Event):
    mac: bytes
    reason: str          # "factory_reset"
```

### 2. Typed status decode — `bridge/mapping.py`

`events_from_app_message` gains a branch for
`msg_id == appmsg.MessageId.REQUEST_STATUS_RESPONSE` returning a
`CommandStatus` built from the already-decoded `messageTag` and `statusCode`
fields (`appmsg.decode_message` parses both at `appmsg.py:153`).

msgId 1 currently falls through to the generic `RawMessageEvent`, which drops
the tag (`body[2:]`). One consumer depends on the old shape:
`tools/sx1302/command_probe.py:111` matches
`isinstance(ev, RawMessageEvent) and ev.message_id == 1` — update it to match
`CommandStatus`.

### 3. Confirm-gated teardown — `bridge/core.py`

- `BridgeCore.__init__` gains `self._pending_reset: dict[bytes, int] = {}`
  (mac → the messageTag the FACTORY_RESET was sent with).
- `submit()` records `self._pending_reset[action.mac] = self._cmd_tag` when the
  action is a `FactoryReset`, after the tag is allocated.
- A new `_intercept(events)` runs before `_emit` on both the `feed()` and
  `tick()` paths. For each `CommandStatus`: if the mac has a pending reset
  **and** `message_tag` matches **and** `status_code == 0`, call
  `_remove_device(mac, "factory_reset")`.
- Any other outcome — tag mismatch, or non-zero status — leaves the record in
  place and logs a warning. A stale record is recoverable; a wrongly-deleted
  one requires a physical re-pair.
- `_remove_device(mac, reason)`:
  - `self._sessions.pop(mac, None)`
  - `self._started.discard(mac)`
  - `self._discovered.pop(mac, None)`
  - `self._pending_reset.pop(mac, None)`
  - `self.store.delete(mac)`
  - emit `DeviceRemoved(mac=mac, reason=reason)`

`tick()` currently iterates `self._sessions.items()` directly; teardown mutates
that dict mid-loop, so it must iterate a snapshot (`list(...)`).

### 4. HA button — `bridge/entities.py`, `bridge/mqtt.py`

```python
# entities.py, COMMAND_BUTTONS
"factory_reset": {"name": "Factory reset", "icon": "mdi:link-off"},

# mqtt.py, _BUTTON_ACTIONS
"factory_reset": lambda mac: FactoryReset(mac=mac),
```

A plain button, consistent with Locate/Reboot. HA users who want a confirmation
step can add one on the dashboard card.

### 5. Entity retraction — `bridge/mqtt.py`

`MqttBridge.on_event` handles `DeviceRemoved`:

- For every discovery config topic previously published for that mac, publish
  an empty retained payload. The set is reconstructible: `_discovery_done`
  holds `f"{machex}_{name}"` keys and `_buttons_done` holds macs; the topics
  come from the existing `discovery_config` / `button_discovery_config`
  builders.
- Clear the retained state topics `{base}/{machex}/{NAME}`, plus
  `{base}/{machex}/availability` and `{base}/discovered/{machex}`.
- Drop the mac from `_discovery_done` and `_buttons_done` so a later re-adopt
  republishes discovery cleanly.

### 6. Control socket

No change. `factory_reset` already parses into the `FactoryReset` action and
inherits the teardown.

## Testing

- `tests/test_bridge_mapping.py` — msgId 1 body decodes to `CommandStatus`
  carrying tag and status; the ground-truth body `013500` yields
  `message_tag=0x35, status_code=0`.
- `tests/test_bridge_core.py`
  - submitting `FactoryReset` records the pending tag;
  - a matching `CommandStatus` with status 0 removes the session, calls
    `store.delete`, and emits `DeviceRemoved`;
  - a mismatched tag does not tear down;
  - a matching tag with non-zero status does not tear down;
  - teardown during `tick()` does not raise (snapshot iteration).
- `tests/test_bridge_mqtt.py` — a `factory_reset` press submits a
  `FactoryReset`; `DeviceRemoved` publishes empty retained payloads to the
  device's discovery topics and clears the done-sets.

## Known gap

Teardown is confirm-only, with no fallback timeout. If a sensor resets without
ever sending the status — `command_probe.py:110` notes these commands "may
reply with a status (msgId 1) or nothing", though the capture above shows this
one does reply — the bridge keeps a record with dead keys and the HA entities
never go away. Recovery is manual: delete the record from the store JSON and
restart the daemon.

Deliberately not built now. If it shows up in practice, add a `--reset-timeout`
escape hatch that tears down after N seconds regardless.
