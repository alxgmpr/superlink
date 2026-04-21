# Open SuperLink Gateway — Plan to Full Pairing & Ownership

**Mission:** build an open-source gateway for Ubiquiti SuperLink sensors
so the sensors can be used on any hardware, with open data, free of
Ubiquiti's controller / cloud. Sensors out of the box should be able to
pair with our gateway and report events to any consumer (MQTT, HTTP,
Home Assistant, etc.).

This document tracks what's solved, what's blocking, and the shortest
path to full interoperability.

---

## Major architecture discovery (2026-04-21)

The Ubiquiti bridge is **not a standalone gateway** — it is a
**stateless LoRa↔JSON-RPC relay** that depends on a UniFi controller
for all pairing intelligence.

```
sensor  ←─LoRa──→  bridge  ←──WebSocket JSON-RPC──→  UniFi controller
                                ws://10.1.1.1:41522
```

Confirmed by hooking `send`/`recv` on the bridge and catching the
WebSocket handshake + JSON traffic live during a pair:

- Bridge connects to the controller at `ws://10.1.1.1:41522` using
  mutual-TLS-style auth (`/etc/persistent/lorabr.{cert,key}`).
- JSON-RPC envelope pattern: `{"id": <uuid>, "name":"<event>",
  "type":"event"|"response", "timestamp":<epoch_ms>, ...}`.
- Controller holds **all per-sensor secrets** (the `keypair+0x30`
  context, outer keys, device identity). Sent to the bridge lazily
  during pairing via JSON-RPC requests.
- Bridge forwards sensor 0x54 uplinks to the controller as JSON events
  (`messageReceived` with hex-encoded `"data"` field).
- Bridge receives `devsInfoChanged` / `discoveryResult` events from
  controller carrying adoption state, `networkId`, `ssid`, MAC, etc.

**The 70-byte Class B grant in the 0x74 DL reply to the sensor's 0x43
is computed locally by the bridge from session state**, but the entire
framework of "what session is this / which sensor / what keys"
originates from the controller. Reproducing the grant without the
controller-provided state is possible in principle but fighting
upstream.

**Consequence for the open-gateway goal:** the cleanest path is to
*replace the controller*, not reverse-engineer every bridge-local
decision. A mock UniFi controller that the real bridge speaks to
(short-term) — or eventually, a full open replacement for both bridge
and controller (long-term) — is the actual deliverable.

Full WebSocket API findings in
[`docs/protocol/controller_websocket_api.md`](protocol/controller_websocket_api.md).

---

## Current state

### Solved (protocol layer)

1. **LoRa PHY** — SF5, 125 kHz UL / 500 kHz DL, CR 4/5, sync 0x1424,
   explicit header. 8 UL + 8 DL paired channels, 915.6–924.6 MHz, plus
   beacon channel 927.6 MHz.
2. **Frame format** — 10-byte cleartext header (mctrl + dctrl + 6B MAC +
   seq_hi + seq_lo) + 4-byte BLAKE2b-truncated MIC + XSalsa20-encrypted
   body. 24-byte nonce is `header(10B) || zeros(13B) || counter(1B)`.
3. **Outer pairing key** — hardcoded Ubi default
   `47be3dffb41ea357…045c2dbe` works for all initial handshake frames
   (0x40 / 0x62 / 0x42) against a factory-reset sensor.
4. **Session-key KDF** —
   `blake2b-32(shared_secret || gw_pub || sensor_pub || keypair+0x30)`.
   All four inputs confirmed via keyhook capture at the exact gh_init
   → 4×gh_update(32B) → gh_final sequence.
5. **ChallengeRsp inner plaintext** —
   `gw_mac(6B) || sensor_mac(6B) || u32(4B)`. The u32 is recovered from
   a 10-byte XSalsa20-encrypted blob at `0x42 payload[35:45]`
   (session_key, zero nonce).
6. **Post-ACTIVE management sequence counter** — position 1 of each
   reply body increments by 1 per DL management frame:
   - `0x53` reply → `09 NN`
   - `0x44` reply → `0b (NN+1) 11 01 0d 14`
   - `0x43` reply → `02 (NN+2) <64B structured> 00 00 04 8f`
   NN is session-specific. The sensor's 0x44 UL body starts with
   `0a NN` — the sensor echoes the DL-counter it expects.
7. **`networkId = 1167 = 0x048F`** is the UniFi network identifier,
   embedded as the stable trailer `00 00 04 8f` in every 70B grant.
   Comes from the controller in `discoveryResult` /
   `devsInfoChanged` events.
8. **Tooling**
   - Standalone gateway emulator on Raspberry Pi + SX1302
     ([`tools/sx1302/superlink/gateway.py`](../tools/sx1302/superlink/gateway.py)).
   - LD_PRELOAD libsodium hook
     ([`tools/keyhook/keyhook.c`](../tools/keyhook/keyhook.c)) —
     captures BLAKE2b state, XSalsa20 IO, Curve25519 scalarmult,
     `randombytes_buf`, `memcpy`/`memmove`/`memset`, `send`/`recv`
     (WebSocket), plus manual ARM stack walker for caller identification.
   - Bundled gdbserver for ARMv7l embedded target at
     `tools/keyhook/gdbserver-armhf` + libs needed at runtime.
   - Heltec V3 passive sniffer
     ([`tools/sniffer/`](../tools/sniffer/)).
   - Capture artifacts under
     [`captures/live/`](../captures/live/).

### Solved (architecture layer)

- Bridge ↔ controller uses deflate-compressed WebSocket, JSON-RPC
  envelopes with one-byte type prefix:
  - `r` = response (to a bridge request)
  - `o` = oneway/event (controller push)
- Bridge requests specific per-sensor data from controller (e.g. the
  `"key"` field — the `keypair+0x30` context) via named methods.
- Bridge emits per-sensor events upstream (sensor data, discovery,
  state changes).

### Not solved (the remaining blocker)

**The 70-byte Class B grant content** (the 64 middle bytes between the
stable `02 NN` header and the `00 00 04 8f` trailer) is built locally
by the bridge via byte-by-byte inline stores. These stores are
compiled as individual `strb` instructions invisible to LD_PRELOAD.

Observed generation path (pair7 2026-04-21):
1. Bridge builds a hex-string representation of the grant char-by-char
   via `std::string::push_back`
2. Bridge calls `sub_327c4` (hex-string-to-bytes decoder) to convert
   that hex string back to binary at a heap address
3. Binary is MIC'd with BLAKE2b, XSalsa20-encrypted with session_key,
   and transmitted

The inline byte stores that produce each hex char from binary state
are the only remaining gap. They operate on values derived from
session state (session_key, sensor MAC, counters, timing). We cannot
observe them without kernel hardware-breakpoint support — which this
bridge's kernel lacks (`CONFIG_HAVE_HW_BREAKPOINT=n`).

Our emulator currently hardcodes a 64B middle copied from one
captured session. The sensor rejects it (continues to retry 0x43 every
~34 seconds) because the byte contents are session-specific and won't
match a new session's derived state.

---

## The per-device secret problem (still real)

Even after pairing works, the per-device `keypair+0x30` context is
controller-provisioned. We've confirmed this: the value
`c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db` is
constant across pair4/5/6 of the same sensor, but arrives from the
controller in JSON (`"key":"..."` field response) each time the bridge
restarts. It's not baked into sensor firmware — it's in the
controller's device DB.

For a fully open gateway, we need either:
- Universal factory default that every factory-reset sensor accepts
  (we can only know by pairing a second, different sensor).
- Derivation from sensor identity (MAC + a master secret we can
  extract from somewhere).
- **Our own controller** that provisions whatever we want.

---

## Plan pivot — Option Y: mock UniFi controller

Instead of chasing every bridge-local decision, stand up a **minimal
mock controller** that satisfies the real bridge's JSON-RPC
expectations. This flips the problem:

- We control what `"key"`, `"secret"`, `"networkId"`, etc. values the
  bridge sees.
- We observe what JSON-RPC *methods* the bridge calls (the full list
  of what it needs from a controller).
- We learn the exact JSON schema for the Class B grant path if it
  turns out the bridge ever asks the controller for one.
- Once the mock controller is rich enough to drive a complete pair, we
  can either (a) keep the bridge binary and run our own controller, or
  (b) reimplement the bridge too for a fully open stack.

This is also the **architecturally correct deliverable** for the
open-gateway mission: sensors need a paired bridge + controller combo,
and the controller is the part more amenable to open-source
replacement.

### Phase Y1 — WebSocket server handshake (hours)

Implement a Python `websockets`-based server:
- Listens on `0.0.0.0:41522`.
- Accepts `permessage-deflate` extension.
- Speaks the JSON-RPC envelope format (`r` / `o` prefix bytes,
  message framing).
- Doesn't need mTLS if we can point the bridge at an unencrypted
  endpoint. If mTLS is required (likely), use the bridge's existing
  cert/key or a self-signed pair the bridge trusts.

### Phase Y2 — Redirect bridge to the mock (hours)

Three viable methods:
- **DNS override**: point the bridge's controller hostname at our
  mock. Requires finding the hostname in the bridge's config.
- **IP takeover**: run the mock on `10.1.1.1:41522` (the real
  controller's endpoint) by isolating the bridge on a separate network
  segment.
- **Binary patch**: modify the hardcoded endpoint in lorabrd (last
  resort — fragile).

Most direct: move the bridge to an isolated LAN with a mock running at
the expected controller IP.

### Phase Y3 — Replay controller responses from captured JSON (1 day)

Use the pair6/pair7 captures as a starting script. Respond to each
JSON-RPC method with a canned reply that matches what the real
controller sent. The bridge should walk through the adoption flow.

At each point where the bridge blocks waiting for a controller reply
we haven't recorded, extend the mock.

### Phase Y4 — Drive an adoption end-to-end (1 day)

With canned replies in place, have the mock answer `devsInfoChanged`
events, provisioning `key`/`secret`/`networkId`/etc. values. If the
bridge then successfully pairs a sensor, we have:

- A deterministic pair reproducible without UniFi's cloud.
- Ground truth for every JSON field required.
- A way to inject *our own* values (including crafted `key` contexts)
  and observe how the bridge/sensor react.

### Phase Y5 — Generalize across sensors (1 week)

Pair a second, different factory-reset sensor via the mock. See what
the mock needs to generate (random `key`? derive from MAC?) to make
the new sensor succeed. This answers the universal-vs-per-device
question empirically.

### Phase Y6 — Replace the bridge (optional, long term)

Once the mock is rich enough that we understand the full JSON-RPC
protocol both directions, we can write an open-source *bridge*
(handling LoRa ↔ controller) that works with the mock. That's the
final open stack: open sensor firmware (future), open bridge, open
controller.

---

## Retained as reference — Option X (static RE, parked)

Fully decompile `sub_52e78` and trace every field that lands in the
70B grant. This was the original plan and is still viable, but it's a
much larger time commitment and produces a per-sensor-specific
patched emulator rather than a scalable open gateway. Revisit only if
Y stalls.

Retained notes:
- `sub_52e78` is the `0x43` inner-type-3 handler, strings
  "SwitchClassBRsp" / "Switch to [ClassName]".
- Timing accessors: `sub_577a6`, `sub_576fc` (returns `arg+0xc` =
  beacon period), `sub_56d0e` (returns `arg+0x40` = timing context),
  `sub_577d4` (next beacon slot index), `sub_51036` (connection queue
  capacity flag).
- Body assembly: `sub_567bc` wraps the body, calls `sub_55eb6` for
  MIC+outer-encrypt. `sub_3bff8` is the XSalsa20 wrapper
  (`→ sub_2f682 = crypto_stream_xor`).
- ChallengeRsp path is `sub_52090` (fully understood).

---

## Status tracker

| Item | Status |
|------|--------|
| LoRa PHY | ✅ |
| Frame format + MIC | ✅ |
| Outer encryption | ✅ factory default |
| DH + session-key KDF | ✅ all 4 inputs confirmed |
| ChallengeRsp layout | ✅ |
| Post-ACTIVE handshake replies | ✅ counter logic understood |
| `networkId = 0x048F` in 0x43 trailer | ✅ |
| Controller JSON-RPC API discovered | ✅ partial schema captured |
| Class B grant 64B middle content | ❌ blocked — local byte-store generation invisible |
| Sensor reaches paired state | ❌ blocked on Class B grant OR mock controller |
| Works on arbitrary factory sensor | ❌ blocked on mock controller replay |
| Mock UniFi controller handshake | ✅ Phase Y1-Y2 done — mock connects to real bridge |
| Drive end-to-end pair via mock | ❌ next milestone — Phase Y3 |

**Phase Y1-Y2 results (2026-04-21):** Mock controller at
[`tools/mock_controller/server.py`](../tools/mock_controller/server.py)
successfully handshakes with the real bridge. Requirements discovered:
bridge is the WSS server on `:8571`, requires mTLS with any
CN=localhost client cert (bridge's own `lorabr.cert/key` works),
`Sec-WebSocket-Protocol: ucp4`, and `X-Mode: 0` header.

Next concrete step: **Phase Y3** — replay captured JSON-RPC requests
against the mock's connection and observe bridge responses. The
bridge doesn't push events on our new connection spontaneously (it's
request-driven), so we need to drive the flow with synthetic
requests from the mock.
