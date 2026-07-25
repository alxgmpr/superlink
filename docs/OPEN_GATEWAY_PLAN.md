# Open SuperLink Gateway — Status & Plan

**Mission:** an open-source gateway for Ubiquiti SuperLink sensors so they
can run on any hardware, with open data, free of Ubiquiti's controller and
cloud. A factory-reset sensor should pair with our gateway out of the box and
report its events to any consumer (MQTT, HTTP, Home Assistant, …).

This document tracks what's solved, what's next, and keeps the reverse-
engineering history as reference. It was substantially rewritten on
**2026-07-24** after the project outgrew the original mock-controller plan.

---

## Where we are (2026-07-24) — TL;DR

**We replaced the entire Ubiquiti stack.** A standalone gateway on open
hardware (Raspberry Pi + SX1302 concentrator) pairs SuperLink sensors
**directly** — no Ubiquiti bridge, no UniFi controller, no cloud:

```
sensor  ←─LoRa──→  superlink-gw  (Pi + SX1302)  ──→  MQTT / Home Assistant / …
```

The full device lifecycle works end-to-end against a real motion sensor:

- **discover → pair → adopt → operational telemetry** (Curve25519 DH →
  BLAKE2b session-key KDF → XSalsa20-Poly1305 frames; ADOPT_REQUEST/RESPONSE
  key rotation; decrypted `ext_report` battery/temperature).
- **reconnect** — rejoin an already-adopted sensor from persisted addDevice
  keys, no re-pair needed (`superlink-gw --reconnect`).
- **over-the-air factory reset** — the gateway can unpair a sensor by sending
  a `FACTORY_RESET` in its 0x53 command window (no physical access needed).
- **v1 and v2 sensor firmware** — see the v2 section below.

Two things that used to look like hard blockers are resolved:

- The controller-provisioned **per-device `keypair+0x30` secret** turned out
  to be a **global default** (`c5923a86…`), accepted by any factory-reset
  sensor. Not per-device, not a blocker. (See "The adoption key" below.)
- We do **not** need to reverse-engineer every bridge-local decision or run a
  mock UniFi controller — the standalone gateway owns the whole flow.

**The current frontier is productization, not protocol.** The open bridge
stack (BridgeCore engine + `superlink-bridged` runtime daemon + MQTT/Home
Assistant adapter, PRs #5–#8) is code-complete and unit-tested, but has
**not yet run on the Pi** — the hardware still runs the older single-file
`gateway.py` monolith that all the live pairing was proven on.

---

## What's solved

### Protocol layer

1. **LoRa PHY** — SF5, 125 kHz UL / 500 kHz DL, CR 4/5, sync 0x1424,
   explicit header. 8 UL + 8 DL paired channels, 915.6–924.6 MHz, beacon on
   927.6 MHz.
2. **Frame format** — 10-byte cleartext header (mctrl + dctrl + 6B MAC +
   seq_hi + seq_lo) + 4-byte BLAKE2b-truncated MIC + XSalsa20-encrypted body.
   24-byte nonce = `header(10B) || zeros(13B) || counter(1B)`.
3. **Outer pairing key** — hardcoded Ubi default `47be3dff…045c2dbe`
   encrypts the initial handshake frames (0x40 / 0x62 / 0x42) against a
   factory-reset sensor.
4. **Session-key KDF** — `blake2b32(shared || gw_pub || sensor_pub ||
   context)`, all four inputs confirmed via keyhook capture. The `context`
   (keypair+0x30) is the adoption key for initial pairing (see below) and the
   rotated `addDevice.key` after commit.
5. **ChallengeRsp inner plaintext** — `gw_mac(6B) || sensor_mac(6B) ||
   u32(4B)`. The u32 is recovered from a 10-byte XSalsa20 blob at `0x42
   payload[35:45]` (session_key, zero nonce). The inner sensor_mac doubling
   as a decrypt oracle is what let us solve the v2 KDF (below).
6. **Adoption** — `ADOPT_REQUEST` (0x02, 70B: `messageId || tag ||
   gatewayPub || gatewayFallbackPub || networkId`) and the sensor's plaintext
   `ADOPT_RESPONSE` (0x03, 66B: two fresh device ephemeral pubkeys). Both
   sides derive persistent `(addDevice.key, addDevice.fallbackKey)` via the
   persistent-key KDF `E` below. `networkId = 0x048F` (1167).
7. **Persistent-key KDF `E`** (from UniFi Protect `deviceAdopt.ts`):
   ```
   H = 70be68514ce7b81328d9f3215855c5675336ea88a08a728df7fce95cc8970a59  (baked-in salt)
   E(my_priv, their_pub) = blake2b32( X25519(my_priv, their_pub)
                                     || base*my_priv || their_pub || H )
   addDevice.key         = E(r, devicePublicKey)
   addDevice.fallbackKey = E(o, deviceFallbackPublicKey)
   ```
8. **Post-commit reconnect** — the adopted sensor re-emits adopted-form
   discovery (`02ae94 NN 0000048f …`) and re-handshakes using the
   `addDevice.key` as session-KDF context and `fallbackKey` as the outer
   transport key.

### Pairing + adoption run end-to-end (standalone gateway)

The Pi gateway (`tools/sx1302/superlink/gateway.py`, driven by `superlink-gw`)
takes a factory-reset sensor all the way to an operational session and holds
it: discovery → 0x62 ConnRsp → 0x42 ConnChallenge → session key → 0x62
ChallengeRsp → 0x53 → ADOPT_REQUEST → ADOPT_RESPONSE → 0x63 commit-ack →
*COMMIT OBSERVED* → key rotation → sustained decrypted `0x54 ext_report`
telemetry. Reconnect and remote factory-reset both verified live.

### The adoption key is a global default (per-device-secret problem resolved)

The value `c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db`
— originally observed as the controller-pushed `"key"` field and assumed to
be a per-device secret — is the **global `LORA_DEVICE_DEFAULT_ADOPTION_KEY`**.
A factory-reset sensor accepts it as the initial-pairing session-KDF context
with no controller provisioning. This is what makes an open, controller-free
gateway viable for arbitrary sensors (pending confirmation on a second
physical unit — see What's next).

### v2 sensor firmware support (PR #8, 2026-07-24)

The bench sensor's firmware was upgraded to a v2 protocol (via OTA
push/revert cycling) that changed two things, both now handled:

| | v1 | v2 |
|---|---|---|
| Discovery ad | `01 ae94 NN 00000000` (8B) | `02 ae94 NN 00000000 0002` (10B) |
| Initial-pairing session-KDF context | `pairing_key` (`47be3dff…`) | adoption key (`c5923a86…`) |

The gateway now gates discovery on the stable `ae94` marker (accepts either
version) and selects the session-KDF context by the discovery version byte,
so a plain `superlink-gw --mac …` pairs both firmwares with no flags.
Hardware-verified including a full factory-reset → fresh no-flag re-pair.
Details in memory `v2_firmware_pairing`.

### Tooling

- **Standalone gateway** — `tools/sx1302/superlink/` (HAL, decoder, crypto,
  gateway state machine, CLI). Entry points `superlink-gw` (pairing),
  `superlink-sniff` (passive), `superlink-bridged` (runtime daemon). Runs on
  the Pi at `alex@sx1302.local`; deploy with `tools/sx1302/deploy.sh`.
- **Open bridge stack** — `tools/sx1302/superlink/bridge/`: `BridgeCore`
  (multi-device registry + persistence), profile registry, event/action
  surface, MQTT/Home-Assistant adapter, YAML config. Code-complete, unit-
  tested, **not yet hardware-run**.
- **LD_PRELOAD keyhook** — `tools/keyhook/keyhook.c`: captures BLAKE2b state,
  XSalsa20 I/O, Curve25519 scalarmult, and (on the real bridge) SSL_read/
  write WebSocket JSON. How the session-KDF inputs were confirmed.
- **Heltec V3 passive sniffer** — `tools/sniffer/`.
- **Capture artifacts** — `captures/live/`.

---

## What's next (prioritized)

### 1. Run the refactored bridge stack on hardware — the current frontier

`superlink-bridged` (BridgeCore + runtime + MQTT) has never paired a sensor
on the Pi; the monolith is what all live pairing used. Bring the refactored
stack up on hardware and reproduce a full pair + adopt + telemetry through
it. **Gate:** first resolve the 2 red `test_gateway.py` ConnChallenge tests
(the `[3:35]` vs `[13:45]` pubkey-offset baseline, memory
`connchallenge_offset_open`) — don't trust the refactored path on hardware
while those fail. Fold the monolith's v2 fixes (already mirrored into
`bridge/session.py`) into the stack of record so the two stop diverging.

### 2. End-to-end Home Assistant demo — the mission headline

Point the MQTT adapter at a real broker + HA instance and get the motion
sensor to appear in Home Assistant reporting battery / temperature / motion,
with zero Ubiquiti software in the loop. This is the deliverable that proves
the mission; it's within reach once #1 is on hardware.

### 3. Pair a second, different sensor — confirm universality

Every live pair so far has been one physical unit (`90:41:B2:2E:9A:53`).
Pairing a second sensor confirms the pairing key, adoption key, and KDF are
truly universal rather than a quirk of this device — the last open question
behind "works on arbitrary factory sensor."

### 4. OTA firmware decrypt key (separate long-term track)

Extract the per-product `.ota` decryption key from the STM32WLE5 sensor via
EMFI RDP1→RDP0 downgrade. Software paths are exhausted; this is a hardware RE
effort. See `docs/emfi_rdp_downgrade_plan.md` and memory
`ota_format_and_emfi_plan`. Not on the gateway critical path.

---

## Status tracker

| Item | Status |
|------|--------|
| LoRa PHY / frame format / MIC | ✅ |
| Outer encryption (factory default) | ✅ |
| DH + session-key KDF (all 4 inputs) | ✅ |
| ChallengeRsp layout | ✅ |
| ADOPT_REQUEST/RESPONSE + persistent-key KDF | ✅ recovered from Protect bundle |
| Sensor reaches paired/adopted state | ✅ standalone gateway, end-to-end |
| Operational telemetry decrypt (0x54 ext_report) | ✅ battery + temperature |
| Reconnect to adopted sensor | ✅ `--reconnect` |
| Over-the-air factory reset | ✅ `--factory-reset` hook |
| Per-device secret / adoption key | ✅ global default `c5923a86…` |
| v1 + v2 firmware pairing | ✅ PR #8 |
| Works on arbitrary factory sensor | 🟡 proven on 1 unit; needs a 2nd |
| Refactored bridge stack on hardware | ❌ never run on the Pi |
| 2 ConnChallenge unit tests | ❌ red baseline |
| End-to-end Home Assistant | ❌ not yet demonstrated |
| OTA firmware decrypt key | ❌ EMFI track, separate |

---

## Reference — how we got here

### Superseded approach: mock UniFi controller (Option Y)

Early RE established that the Ubiquiti bridge is a **stateless LoRa↔JSON-RPC
relay** that depends on a UniFi controller (over `ws://…:41522`,
`permessage-deflate`, JSON-RPC with `r`/`o` prefix bytes) for all pairing
intelligence — per-sensor keys, identity, `networkId`, the 70-byte body, etc.

The plan then was to stand up a mock controller that the real bridge speaks
to (Phases Y1–Y5), and eventually replace the bridge too. We got the mock
handshaking with the bridge and drove the bridge side of a pair to
`adopted=true`, but the sensor side stalled on replayed (stale) ephemerals —
the exchange is a two-way Curve25519 ratchet, so canned rotation values
diverge from the sensor's fresh response.

**Why this is parked:** rather than satisfy every bridge-local expectation,
we built a standalone gateway that owns the LoRa side directly and provisions
its own values — replacing bridge *and* controller. The mock-controller work
lives on in `tools/mock_controller/server.py` and remains useful for probing
the real bridge, but it is no longer the path to the open gateway.

Key artifacts from that effort, still valid as protocol ground truth:

- **The 70-byte body is plaintext `ADOPT_REQUEST`**, not an encrypted grant.
  The "encrypted Class B grant" framing was a multi-week blind alley from
  mis-reading the MSB-clear pattern — both 64B halves are raw X25519 pubkeys.
  Recovered from UniFi **Protect** (not Network): UNVR firmware v5.0.16,
  rootfs squashfs at offset `0xE88D45`, webpack module 41118 (`messages.ts`)
  and `subscribers/deviceAdopt.ts`. See
  `docs/protocol/superlink_application_layer.md`.
- **Controller JSON-RPC vocabulary**: `bridgeInfoGet`, `keyExchange`,
  `authorize`, `discoveryStart`, `addDevice`, `removeDevice`, `sendMessage`;
  events `discoveryResult`, `devsInfoChanged`, `messageReceived`. Captured by
  LD_PRELOAD-hooking `SSL_read`/`SSL_write` (`tools/keyhook/ssl_decode.py`).
  See `docs/protocol/controller_websocket_api.md` and `controller_y3_findings.md`.

### Parked: Option X — full static RE of the grant assembler

Decompile `sub_52e78` (the 0x43 inner-type-3 "SwitchClassBRsp" handler) and
trace every field into the 70B body. Superseded by the ADOPT_REQUEST
recovery above; retained only as a fallback. Notes: body assembly
`sub_567bc` → `sub_55eb6` (MIC + outer encrypt); XSalsa20 wrapper `sub_3bff8`
→ `sub_2f682` (crypto_stream_xor); ChallengeRsp path `sub_52090`.
