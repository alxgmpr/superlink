# Open SuperLink Gateway — Plan to Full Pairing & Ownership

**Mission:** build an open-source gateway for Ubiquiti SuperLink sensors
so the sensors can be used on any hardware, with open data, free of
Ubiquiti's controller / cloud. Sensors out of the box should be able to
pair with our gateway and report events to any consumer (MQTT, HTTP,
Home Assistant, etc.).

This document tracks what's solved, what's blocking, and the shortest
path to full interoperability.

---

## Current state (2026-04-21)

### Solved

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
   `blake2b-32(shared_secret || gw_pub || sensor_pub || context)` where
   `context` is the vector at `keypair+0x30` in firmware.
5. **ChallengeRsp inner plaintext** —
   `gw_mac(6B) || sensor_mac(6B) || u32(4B)`. The u32 is echoed from a
   10-byte XSalsa20-encrypted blob at `0x42 payload[35:45]`.
6. **Post-ACTIVE management flow** —
   `0x53 → 0x74 (0958)`, `0x44 → 0x74 (0b5911010d14)`,
   `0x43 → 0x74 (70B blob)`, all session_key-outer with incrementing
   counter.
7. **Tooling**
   - Standalone gateway emulator on Raspberry Pi + SX1302 concentrator
     ([`tools/sx1302/superlink/gateway.py`](../tools/sx1302/superlink/gateway.py)).
   - LD_PRELOAD libsodium hook for real bridge
     ([`tools/keyhook/keyhook.c`](../tools/keyhook/keyhook.c)) — captures
     BLAKE2b state, XSalsa20 plaintext/ciphertext, Curve25519 scalarmult
     inputs/outputs.
   - Heltec V3 passive sniffer
     ([`tools/sniffer/`](../tools/sniffer/)).
   - Capture artifacts under
     [`captures/live/`](../captures/live/).

### Observed but not fully decoded

- Post-ACTIVE 0x54 UL data frames arrive every ~30 s. Same size (80 B),
  same `03 5a …` prefix every frame. **Not operational data** — this is
  a sensor retry loop while waiting for proper pairing confirmation.

### Not solved (the blocker)

**The sensor does not commit to paired state** after our handshake.
Evidence:

- Sensor's external LED stays white (unpaired colour). Real bridge
  pairing turns it briefly blue then off.
- Physical open / close of the reed switch produces no extra UL frames —
  the sensor is not emitting events.
- 0x54 UL frames arrive on a fixed 30 s cadence regardless of sensor
  state → this is a retry-pairing transmission, not real telemetry.

The most likely root cause is the **70-byte blob in our 0x74 reply to
the sensor's 0x43 message**. Structure:

```
02 5a <64 bytes random-looking> 00 00 04 8f
```

**Update (after RA-logging hook capture 2026-04-21):** the 70-byte
reply is NOT an opaque cryptographic signature. Binary Ninja on
`sub_52e78` (the function that builds it) shows strings **"Switch to
[ClassName]"** and **"SwitchClassBRsp"**. This is a **Class A → Class B
switch grant** — structured beacon/ping-slot timing config in a
LoRaWAN-style encoding. Our hardcoded copy from a different session
doesn't carry valid timing for the sensor's intended beacon, so the
sensor never commits to Class B — which is exactly why the LED stays
white.

This reframes the blocker from "forge a UBNT signature" (probably
impossible) to "encode the Class B grant correctly" (tractable via
firmware RE).

Secondary suspects: the session-varying middle bytes of the shorter
0x74 replies (`09 58` low byte, `0b 59 11 01 0d 14` second byte) are
likely similar structured config (not signed material).

---

## The per-device secret problem

Even before the signing-blob question, pairing is currently
**per-sensor-specific**. Our working emulator hardcodes values
*captured from one real bridge that had already adopted this sensor*:

- `--kdf-context c5923a86…`  — the `keypair+0x30` value
- `--mac 9041B23483DC` — the real bridge's MAC (spoofed into our inner
  plaintext as the "gateway MAC" the sensor knows)

Both values are per-device secrets the UniFi controller provisions to
the bridge when the sensor is adopted.

For a usable open gateway, we need one of:

- **A universal factory default** for both values that every
  factory-reset sensor accepts. (Possible if UBNT uses a shared
  bootstrap key; our `47be3dff…` outer key is already one such universal
  default.)
- **A reproducible derivation** (e.g. `BLAKE2b(MAC || static_constant)`)
  we can compute from the sensor's MAC.
- **A way to extract the sensor's expected value** from a firmware dump.

---

## Plan — ordered by cost / information density

### Phase A — Cheap investigations (hours)

**A1. Check `/etc/persistent/` on the bridge for key material.**
The existing [`lorabr.json`](../captures/) references
`lorabr.cert` and `lorabr.key`. If these contain the signing key used
to generate the 70-byte blob, we can use them directly.

**A2. Find the 0x74-body construction paths in lorabrd.**
Use Binary Ninja. The handlers were registered in `sub_54020`:
- `sub_51af2` at `gw+0x25` — discovery / 0x40 handler
- `sub_524ac` at `gw+0x26` — connection / 0x62 / 0x42
- `sub_53ec6` at `gw+0x26` — management (likely 0x53 / 0x43)
- `sub_53e2e` at `gw+0x27` — management (likely 0x44)

Trace the outbound side: for each of `sub_53ec6` / `sub_53e2e` / similar,
find where the 6-byte / 70-byte 0x74 plaintext is assembled. Identify
the function that produces the 64 "random" bytes — it will call into a
sign/HMAC primitive and use some key.

**A3. Augment the keyhook with a stack-trace printer.**
On `crypto_stream_xor(LEN=74)` log `__builtin_return_address(0..3)`.
That's the call site of the code that just encrypted the 70-byte reply.
Cross-reference the return addresses with Binary Ninja to jump directly
to the construction code (much faster than blind static RE).

**A4. Decompile UniFi Network Application (Java, public download).**
Find where it generates the per-device "key" / "fallbackKey" values it
provisions to bridges. This reveals whether they're random, derived
from MAC, or fetched from a UBNT cloud service.

### Phase B — Decode the Class B grant (1–2 days)

*Revised after 2026-04-21 RA-logging confirmed this is not a crypto
signature but a structured Class B switch-grant message.*

**B1. Map `sub_52e78`'s output structure.**
It's the handler for 0x43 inner type 3 ("SwitchClassBRsp" per strings).
Trace each field that goes into the 70-byte body via `sub_567bc` →
`sub_55eb6`. Expected fields based on LoRaWAN Class B conventions:
- beacon frequency / channel index
- beacon period (default 128 s in LoRaWAN)
- ping slot period / offset
- data rate for Class B downlinks
- timestamp / beacon-time reference

**B2. Decompile beacon/timing accessors used by `sub_52e78`:**
`sub_577a6`, `sub_576fc`, `sub_56d0e`, `sub_577d4` — these pull the
gateway's current beacon schedule. Understand what state the bridge
holds that we must also hold.

**B3. Build + test a valid Class B grant.**
Encode a grant pointing at our gateway's beacon (if we implement a
beacon). Test: sensor should accept the grant, transition to Class B,
LED goes blue then off, door events start arriving.

If our emulator can't match a real beacon (we don't transmit one yet),
we may need to fake "beacon pending" until we also implement the beacon
TX path — check if Class B allows a deferred beacon lock.

### Phase C — Test full pairing (hours)

**C1. Factory-reset sensor, start emulator with replicated blob.**
Expect LED to go blue → off, and door-open events to start arriving.

**C2. Decode 0x54 operational data frames.**
Once paired, fix the UL counter calculation (the
`max(0, seq_hi - ul_counter_offset)` clamping is wrong because the
handshake leaves `ul_counter_offset` = 0xFE from the 0x42 seq). Decode
the `03 5a …` payloads — likely door state + battery + RSSI + timestamp.

**C3. Validate with the reed switch.**
Open / close the sensor and confirm we see event frames, not just
periodic heartbeats.

### Phase D — Generalize to any factory sensor (1 week+)

Depends on whether `keypair+0x30` / outer pairing key are universal
factory defaults, per-device baked-in secrets, or controller-provisioned
random values.

**D1. Pair a second sensor**, capture its `keypair+0x30` and outer key
via the LD_PRELOAD hook. Compare against the first sensor's values. If
identical → universal factory default for fresh sensors. If different →
per-device.

**D2a. If per-device, find the provisioning source.**
UniFi controller generates per-device values — where are they stored /
derived? A1+A4 partial results feed in here. Possibilities:
- UBNT cloud DB keyed by MAC — unreachable
- Derived from sensor MAC + a UBNT master secret — derivable if we find
  the master secret on bridge or in controller
- Random per-controller-install — would mean we need to generate our
  own, which is fine if the sensor has no memory of prior values across
  factory resets

**D2b. If universal factory default**, hardcode in `gateway.py` and ship
a working open gateway that pairs any factory-reset sensor out of the
box. Done.

### Phase E — Sensor-side RE (fallback, ~2 days hardware work)

If Phase D reveals that the sensor validates something tied to UBNT
identity (e.g. the 70-byte blob must be signed by a UBNT-root-trusted
key), we need to either:

- Read sensor flash and find the validation code + trusted root.
- Potentially modify sensor firmware (if practical) to remove the check.

This requires SWD / JTAG or SPI flash access to the USL-Entry sensor
hardware. Out of scope for now — revisit only if Phase D dead-ends.

---

## What "full ownership" looks like

When pairing works end-to-end, our gateway should:

1. Accept `0x40` discovery from any factory-reset USL-Entry sensor.
2. Complete the `0x62 / 0x42 / 0x62 / 0x53 / 0x44 / 0x43` handshake,
   producing a valid 70-byte blob in the 0x43 reply.
3. Sensor LED goes blue → off → paired state.
4. Sensor emits real `0x54` events on reed-switch state change.
5. We decrypt those events and publish them as structured data (MQTT,
   HTTP, HA integration).

After that, stretch goals:

- Multi-sensor support (one gateway, many paired sensors).
- DL command path (turn off the reed-switch LED, trigger an OTA, etc.)
  if the DL direction is useful and safe.
- Firmware OTA passthrough if we don't want to block updates.
- Wireshark dissector for SuperLink frames.

---

## Status tracker

| Item | Status |
|------|--------|
| LoRa PHY | ✅ done |
| Frame format + MIC | ✅ done |
| Outer encryption | ✅ done for factory default |
| DH + session-key KDF | ✅ done |
| ChallengeRsp layout | ✅ done |
| Post-ACTIVE handshake replies | 🟡 literal-copy; structure understood (Class B grant) |
| Class B grant decoded | ❌ next milestone — see Phase B |
| Sensor reaches paired state | ❌ blocked on valid Class B grant |
| Operational data decode | ❌ blocked on paired state |
| Works on arbitrary factory sensor | ❌ blocked on per-device secret story |

Next concrete step: **Phase A1 + A2** (cheap, high-information, can be
done without touching the sensor).
