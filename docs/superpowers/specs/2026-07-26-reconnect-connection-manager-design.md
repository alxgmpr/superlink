# SuperLink bridge — reconnect / connection-manager design

**Date:** 2026-07-26
**Status:** design approved; RE-discovery phase gates implementation
**Scope:** how `superlink-bridged` should hold a sensor connected long-term *and*
reliably deliver commands to it.

## Problem

`superlink-bridged` can complete the pairing/reconnect handshake and decode
telemetry, but it cannot keep a sensor reliably connected, and it has no
dependable way to deliver a command to a connected sensor. Observed on the entry
sensor `9041b22e9a53` (fw 1.2.0) on 2026-07-26.

What we call "the reconnect problem" is really **two** problems that an earlier
naive fix conflated:

- **Problem A — keep-alive.** A happy sensor streams `0x54` telemetry and sends
  *zero* `0x40` discoveries; it only starts re-discovering once it decides the
  gateway is gone. Our bridged sends nothing proactively — it only replies to
  sensor frames. The real Ubiquiti bridge beacons continuously on 927.6 MHz.
  Hypothesis: the beacon is the sensor's "gateway alive" heartbeat, and its
  absence is what eventually triggers re-discovery. Our beacon code is a stub
  (`dctrl = 0x00 # TBD`), so the real beacon format is unknown.
- **Problem B — graceful re-handshake.** When the sensor *does* re-discover
  (fresh `0x40`) while the session is ACTIVE, the gateway must re-establish
  cleanly. The reverted-in-`git`/on-Pi behavior *ignores* `0x40` while ACTIVE
  (holds a stable link but strands the sensor when it genuinely needs to
  reconnect). The naive "fix" re-handshaked on *every* `0x40` with no
  debounce/backoff, turning a panicking sensor's rapid `0x40`s into a tight
  teardown loop (red LED). See memory `bridge_reconnect_loop_negative`.

A third mechanism underlies both and is also unknown: **how the real system
delivers a command to a steadily-connected sensor.** In everything observed, the
`0x53` command window only appeared at handshake. If keep-alive works and the
sensor rarely reconnects, command windows become rare, so we must know how the
real controller nudges one open.

## Goal

Both: (1) the sensor stays green/streaming for hours/days without stranding, and
(2) commands issued via the control socket / MQTT reliably reach a connected
sensor.

## Approach: two tracks, RE-discovery first

### Track A — RE-discovery (gates keep-alive + command delivery)

Two capture sessions against a **real** Ubiquiti bridge (bench device; see memory
`reference_bridge_tooling`), cross-checked against `lorabrd`:

1. **Beacon capture.** Park the SX1302 sniffer (or Heltec, `b` = beacon channel)
   on 927.6 MHz next to a real bridge; capture beacon frames → decode `dctrl`,
   payload layout, and cadence. Confirm against `lorabrd`'s beacon-TX path.
   - *Output:* beacon frame spec + transmit cadence.
2. **Command-window capture.** Sniff a real bridge + UniFi/Protect app session;
   fire a LOCATE at an *already-connected* sensor; capture the frames around the
   sensor's `0x53` window.
   - *Output:* which mechanism the real system uses —
     (a) sensor opens periodic mgmt/command windows on its own cadence, or
     (b) gateway flags "pending command" in a DL reply to a `0x54` and the sensor
     then opens a window.

These outputs are the facts pieces 1–2 of Track B need. Building before we have
them risks designing for the wrong command-delivery mechanism.

### Track B — buildable now (state machine + safe re-handshake)

Buildable without RE data; hardens the failure modes.

**Explicit per-device connection state** (today the state is implicit with *no*
timeout logic at all):

```
BEACONING  -- no session; (later) actively beaconing on 927.6
   | 0x40 discovery (debounced)
HANDSHAKING -- 0x62/0x42 in flight, deriving session key
   | 0x42 -> session key derived
CONNECTED  -- session key live, 0x54 flowing; track last_rx
   | no RX for T_lost (~120 s)
LOST       -- emit availability=offline (MQTT); keep listening
```

**Graceful re-handshake** — the fix for the loop. On a fresh `0x40` while
`CONNECTED`:

- **Debounce:** ignore further `0x40`s while a handshake is already in flight
  (~2 s window).
- **Loop-guard / backoff:** if ≥K re-handshakes complete within a window
  (default K=3 in 30 s) and the sensor *still* re-discovers, enter BACKOFF — stop
  answering `0x40`s for a cooldown (~60 s) instead of hammering. This is exactly
  what would have prevented the observed loop.
- **Preserve** `_pending_bodies`, rotated keys, and adoption state across the
  re-handshake (the one part the naive fix got right).

Tunables (config, with defaults): debounce window (2 s), loop-guard K (3) /
window (30 s) / cooldown (60 s), `T_lost` (120 s).

**Honest caveat:** backoff makes the failure *graceful* (no red-flashing storm)
but does not *cure* it — during backoff the sensor still isn't connected. The
cure is keep-alive (piece 1, Track A) preventing re-discovery entirely. Track B
makes failure survivable; Track A makes it not happen.

## Non-goals / YAGNI

- No speculative beacon transmission until the real beacon format is captured
  (a wrong beacon is no better than none and risks confusing the sensor).
- No multi-sensor scaling work beyond what the per-device state machine naturally
  provides.
- Not re-attempting the naive "re-handshake on every 0x40" — it is a known
  negative result.

## Design for isolation

- **ConnectionState** logic lives in `DeviceSession` (per-device, pure, testable
  with synthetic frames + a `now` clock — same style as existing session tests).
- **Keep-alive beaconing** is a runtime-level periodic task (gateway-wide, not
  per-session), driven off the existing `tick()` path in `BridgeRuntime.run()`
  (currently `tick()`/`_maybe_tick` exists but `run()` never calls it).
- **Backoff/loop-guard counters** are session-local; no shared global state.

## Open questions (resolved by Track A)

1. Real beacon `dctrl` + payload + cadence.
2. Steady-state command-delivery mechanism (sensor-poll vs gateway-flag).
3. Whether the sensor treats beacon absence as the sole re-discovery trigger, or
   also uses a telemetry-ack timeout (informs whether keep-alive alone suffices).

## Sequencing

1. Track A capture sessions → document beacon spec + command-window mechanism.
2. Track B: connection state machine + graceful re-handshake (debounce/backoff),
   TDD, no RE dependency.
3. With Track A results: implement keep-alive beaconing (piece 1) and the
   steady-state command-delivery path (piece 2); revisit Track B tunables in
   light of what was learned.
