# 2026-04-20 Pairing RE Summary

This document summarizes the static reverse engineering and live-capture
findings established during the 2026-04-20 debugging session for initial
pairing and `0x62` / `0x42` handling.

## Scope

Goal of the session:

- determine whether the short `0x42` uplink is a real protocol message or a
  failed/decrypted-garbage artifact
- determine whether the gateway's initial `0x62` ConnectionRsp format was
  fundamentally wrong
- identify the next blocker for full SuperLink pairing emulation

## High-Level Conclusions

1. The observed short `0x42` is **not** the full successful challenge path.
2. The initial gateway `0x62` payload is **41 bytes plaintext** inside a
   55-byte frame, and a real captured gateway frame confirms that.
3. Our emulator already matches the real gateway on the first **9 plaintext
   bytes** of `0x62`.
4. The remaining mismatch is **state generation**, not RF framing.
5. The 7-byte region after `01 01` is **stateful**, not a permanent constant.
6. We still do **not** have enough to claim full independent pairing
   replication end-to-end.

## Live RF Findings

### Our TX is on-air and decodes correctly

The Heltec and SX1302 passive receiver both captured our transmitted `0x62`
frames on the correct paired downlink channel.

Example live capture from the Heltec:

```text
E0 62 90 41 B2 2E 9A 53 07 00 AC 16 D4 03
1D E2 5C F4 49 7A 7D 03 BC 07 5E DE D3 68 DB D5 62 D6
47 B3 2B E1 90 68 94 54 A7 0C 67 62 F3 EF 57 52 F0 F5
BF 88 37 8A 62
```

Decrypted with pairing key and `counter=0`, that yields:

```text
MIC     60288ede
PAYLOAD 010174ad9482f05344961f3ed8caf12885f8711ca81b0896cbfb0a97bc92e8090207f7dbc3cec32e44
```

So our current emulator really sends:

- `01 01`
- `74 ad 94 82 f0 53 44`
- `32-byte trailing field`

### Sensor discovery traffic is still active

Board 1 live logs show the sensor is still emitting discovery messages and the
payload changes every attempt:

```text
01ae942500000000
01ae942600000000
...
01ae943900000000
```

That changing discovery state is important because our current emulated `0x62`
prefix is frozen.

## Real Gateway `0x62` Capture

The repo already contains a real captured gateway `0x62` frame in
`tests/test_decoder.py`.

Raw frame:

```text
e0629041b22e9a538902
cf74f5ab8308752f4a34947fdd262cbfe128958e65e9
e1272713b5516796603c4e07d5d8e256224a210dc6f78a
```

Decrypted with pairing key and `counter=0`:

```text
MIC     2ee4f018
PAYLOAD 010174ad9482f05344dc891d3f70c984c364e0c13861429e6c54e54dad5ec3aa56410a000203feff03
```

This proves:

- initial pairing really does use `dctrl=0x62`
- the frame really is `55` bytes total
- the plaintext payload really is `41` bytes
- the real gateway payload starts with:

```text
01 01 74 ad 94 82 f0 53 44
```

This was a major correction to the earlier assumption that the whole `0x62`
body shape might be wrong. The first 9 plaintext bytes are already correct.

## Comparison: Real `0x62` vs Emulator `0x62`

Real gateway payload:

```text
01 01 74 ad 94 82 f0 53 44
dc 89 1d 3f 70 c9 84 c3 64 e0 c1 38 61 42 9e 6c
54 e5 4d ad 5e c3 aa 56 41 0a 00 02 03 fe ff 03
```

Current emulator payload:

```text
01 01 74 ad 94 82 f0 53 44
96 1f 3e d8 ca f1 28 85 f8 71 1c a8 1b 08 96 cb
fb 0a 97 bc 92 e8 09 02 07 f7 db c3 ce c3 2e 44
```

What matches:

- bytes `0..8`

What differs:

- bytes `9..40`

Interpretation:

- RF framing is not the blocker
- nonce/counter for `0x62` is not the blocker
- the stateful payload contents are still wrong

## Connection Handler Findings

### `sub_524ac` at `0x524ac`

This is the connection dispatcher.

Relevant behavior:

```c
arg1 = sub_32108(arg1 + 0x3c);
if (arg1 != 0) return;
sub_55fe0(&msg, *arg2 + 0x1c, r4 + 0xcc, arg1);
...
switch (type_byte) {
case 0: sub_51914(...);
case 2: sub_52090(...);
}
```

Implications:

- connection-handler decryption proceeds only when `sub_32108(...) == 0`
- the decrypt counter passed here is effectively `0`
- connection inner dispatch is:
  - `0 -> sub_51914`
  - `2 -> sub_52090`

### Connection-frame decrypt counter

`sub_55fe0` calls the decrypt helper labeled `sub_3bff8` in some notes
(decompile start at `0x3c00c`), which constructs the nonce as:

```c
memcpy(nonce, header, 0xa);
memcpy(nonce + 0x14, &counter, 4);
crypto_stream_xor(...)
```

This means the connection-handler path uses the real RF header bytes and a
separate counter field. In the `sub_524ac` path above, that counter is
effectively `0`, not `seq_hi`-derived.

## Initial Request / Response Path

### `sub_51914` at `0x51914`

```c
if (arg4 == *(r2 + 4) - r2) {
    var_c:1.b = 0;
    sub_51742(arg1, arg2, &var_c);
}
```

This is the short initial type-0 path that triggers the first gateway response.

### `sub_51742` at `0x51742`

This builds the initial gateway `0x62`.

```c
char state = *(arg1 + 0x25);
char seq = *(arg1 + 0x220) + 1;
*(arg1 + 0x220) = seq;

sub_444b8(&obj, 2, state, arg1 + 0x44, flag, arg3, seq);
sub_439f0(&obj, 1);
...
sub_55eb6(&mic, &serialized, arg1 + 0xcc, nullptr);
sub_57ee8(..., arg4=0, ...);
```

Implications:

- gateway maintains a dedicated TX sequence byte at `gateway + 0x220`
- the initial response object includes:
  - constant `2`
  - gateway state byte
  - copied blob from `gateway + 0x44`
  - optional/extra field
  - TX sequence byte
- another discriminator `1` is stamped via `sub_439f0`

### `sub_57ee8` at `0x57ee8`

```c
if (arg4 == 0)
    sub_49202(...)
else
    sub_49358(...)
```

The initial response goes through `sub_49202`, not the alternate path.

## Response Object Layout Findings

### `sub_444b8` at `0x444b8`

```c
*(arg1 + 0x4d) = arg2;        // constant 2
*(arg1 + 0x4e) = arg3;        // gateway state byte
std::vector<uint8_t>::operator=(&arg1[0x15]);   // copy blob from gateway+0x44
*(arg1 + 0x75) = arg5;        // flag
arg1[0x1d].b = zx.d(arg6[1]); // optional-present flag
if (r3_1 != 0) *(arg1 + 0x76) = *arg6;
else sub_43f2c(&arg1[0x19]);
arg1[0x18].b = arg7;          // tx sequence
```

This is the clearest static proof that the first `0x62` is stateful.

### `sub_439f0` at `0x439f0`

```c
*(arg1 + 0x1d) = arg2;
arg1[7].b = 1;
```

Called with `arg2 = 1` on the initial response path.

## Random / Optional Field

### `sub_43f2c` at `0x43f2c`

This function initializes a bounded random value:

```c
data_10d6e8 = 0;
data_10d6e9 = 0x3f;
...
*(arg1 + 0x12) = result;
```

Implication:

- at least one field in the first `0x62` can be generated dynamically
- our current hardcoded payload cannot be fully correct

## Discovery Handler State Packaging

### `sub_51af2` at `0x51af2`

This is the discovery handler.

Important sequence:

```c
sub_55fe0(&var_f4, *arg2 + 0x1c, r4 + 0xd8, arg1);
...
sub_48832(&var_a8, r4 + 0x44, zx.d(var_b2), (*(*arg2 + 0x18)).w, var_b0, var_ac);
sub_491f2(r6_4, &var_a8, r4 + 0xd8);
...
sub_51742(r4, arg2, &var_a8);
```

This is the strongest clue about the mysterious `gateway + 0x44` blob:
discovery-time state is packaged into an object and then passed into the
session-request path.

### `sub_48832` at `0x48832`

```c
sub_4dc64(&arg1[1], arg2 + 4);   // copy vector from gateway+0x44
arg1[4].w = arg3.w;              // 16-bit field
*(arg1 + 0x12) = arg4;           // 1-byte field
arg1[5].b = r7.b;                // flag
if (r7 != 0 && arg6 != 0) {
    arg1[6] = arg6;
    arg1[7].b = 1;
}
```

This supports the idea that the 7-byte header-like region in the initial
`0x62` is a compact serialized discovery/session descriptor, not a literal
fixed constant.

## Wrapper / Serializer Findings

### `sub_443c0` / `sub_43e54`

The serializer wrapper path bakes in fixed control values:

`sub_443c0`:

```c
arg1[7].b = 0xe0;
sub_2f798(&arg1[0xd], sub_43e54(&arg1[8]));
arg1[0x11].b = 0;
sub_43ec0(&arg1[0x12]);
```

`sub_43e54`:

```c
arg1[4].w = 0x201;
*(arg1 + 0x12) = 0;
```

### `sub_3c10c`

This is the compact control-byte serializer:

```c
var_byte |= ...
*out = var_byte;
```

It serializes bitfield-descriptor nodes created by `sub_3bc94` and
`sub_3bd0c`. This explains why object-field offsets do not directly map to the
wire layout.

## `0x42` Challenge Path Findings

### `sub_52090` at `0x52090`

Critical size check:

```c
r8_1 = arg3[1] - *arg3 - arg4;
if (r8_1 >= 0x2c && r8_1 <= 0x4c) {
    ...
    sub_3af5a(arg1 + 0x54, &var_1b8, &var_c0);
}
```

Implication:

- the successful type-2 challenge path still expects a **large** payload
- the observed **16-byte** `0x42` is **not** this full successful path

This remains true even after the `0x62` corrections above.

## Answers to Key Questions

### Is `0x42` always 16 bytes?

No.

Static RE still shows a successful large challenge path in `sub_52090`, and the
repo's earlier captures also document larger `0x42` frames in other handshake
contexts.

### Is the initial `0x62` frame fundamentally the wrong size/shape?

No.

The real gateway uses:

- `dctrl = 0x62`
- `55` bytes total
- `41` bytes plaintext payload

and our emulator already matches the first 9 plaintext bytes.

### What is still wrong in our `0x62`?

The **stateful contents**.

Specifically:

- the copied blob sourced from `gateway + 0x44`
- the trailing 32 bytes
- any optional/random field embedded by the real firmware

## Resolved Layout (2026-04-20 afternoon pass)

The `0x62` and `0x42` plaintext structures were cracked by splitting on the
shared trailer `03 fe ff 03` that appears at the end of **both** frames —
impossible by chance for random pubkeys (1-in-4-billion).

### `0x62` ConnectionRsp (41 bytes)

```
[0:2]   01 01                    (outer type, inner_type=ConnRsp=1)
[2:34]  <32-byte gateway pubkey> (Curve25519, regenerated per-session by sub_3af20)
[34:37] 0a 00 02                 (random 0..63, optional-present=0, const 2 from sub_444b8)
[37:41] 03 fe ff 03              (fixed ChMap trailer)
```

Earlier reading had the pubkey at offset 9 behind a "captured 7-byte header"
(`74 ad 94 82 f0 53 44`). Those seven bytes in the real capture were **the
first 7 bytes of the gateway's Curve25519 pubkey**, mistaken for a constant.

### `0x42` ConnectionChallenge (49 bytes)

```
[0:2]   01 02                    (outer type, inner_type=Challenge=2)
[2:13]  01 5d 0b 05 68 21 90 f8 b4 06 2b  (11-byte challenge/state header)
[13:45] <32-byte sensor pubkey>  (Curve25519)
[45:49] 03 fe ff 03              (fixed ChMap trailer — same as 0x62)
```

Earlier reading extracted pubkey at `[17:49]`, which silently swallowed the
`03 fe ff 03` trailer into the pubkey. Real Curve25519 pubkeys do not end
in that magic.

### `0x62` ChallengeRsp (41 bytes)

Built by `sub_52090` via the same `sub_444b8` path as ConnRsp but with
`sub_439f0(obj, 3)` instead of `1`, so `inner_type = 3`:

```
[0:2]   01 03
[2:34]  <32-byte gateway pubkey> (same keypair as ConnRsp)
[34:37] 0a 00 02
[37:41] 03 fe ff 03
```

## Session Key KDF (sub_3af5a)

After `crypto_scalarmult(shared, local_priv, remote_pub)`, the firmware does:

```c
r6 = &remote_pubkey   // keypair + 8
r8 = &local_pubkey    // keypair + 0x14
if (keypair+4 == 0)   // NOT initiator (the gateway case)
    swap(r6, r8)
blake2b_update(shared)
blake2b_update(*r6)   // after swap: local (gateway_pub)
blake2b_update(*r8)   // after swap: remote (sensor_pub)
```

So **both sides** hash `shared || gateway_pub || sensor_pub`. The prior
emulator hashed `shared || sensor_pub || gateway_pub`, producing a key the
real sensor would never agree with — a silent interop bug masked by
self-consistent unit tests.

## Emulator Changes Landed

- `tools/sx1302/superlink/gateway.py`
  - 0x40 branch: emit `01 01 | pubkey | 0a 00 02 | 03 fe ff 03`.
  - 0x42 branch: extract `remote_pubkey` from `[13:45]`, validate trailer.
  - ChallengeRsp: emit same layout with `01 03` prefix.
  - KDF call fixed to `derive_session_key(shared, gw_pub, sensor_pub)`.
- `tools/sx1302/superlink/crypto.py`: docstring corrected to match firmware.
- `tests/fixtures/captured_frames.py`: `CONN_CHALLENGE_SENSOR_PUBKEY = PAYLOAD[13:45]`
  (was `[17:49]`).
- `tests/test_gateway.py`: DH-ordering tests plus crafted-0x42 test updated
  for the new pubkey offset and KDF order.

All 34 tests pass. End-to-end simulation: gateway and sensor-side code now
derive an identical session key from a crafted 0x42 using the real wire
layout; the TX MIC verifies against the same BLAKE2b-4 scheme proven against
the real captured 0x62.

## Still Open

- The 11-byte mid-header of `0x42` (`01 5d 0b 05 68 21 90 f8 b4 06 2b`) is
  probably challenge material + ChMap echo; not yet field-mapped.
- The `0a 00 02` middle of `0x62` is semantically just copied from capture.
  Plausibly `{random 0..63 from sub_43f2c, optional-present=0, const 2}`.
- After ACTIVE: sensor sends 0x44 Setup frames with session key; we decrypt
  but don't yet reply with 0x74.
