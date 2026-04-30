# Controller WebSocket — Y4 mock-driven pair results

Phase Y4 of the [open-gateway plan](../OPEN_GATEWAY_PLAN.md). Goal:
drive a real Ubiquiti SuperLink bridge through a complete sensor pair
using our mock controller, replaying the captured Y3 script.

## Status

**Implementation complete, framing verified live, crypto chain
confirmed correct, but Phase 1 blocked on per-connection EXPECTED
selection.** The bridge runs `crypto_secretbox_open_easy` over the
base64-decoded secret with key/nonce we now correctly derive — the
PT decodes cleanly. The remaining blocker is that the bridge's
`memcmp` target (`[auth_state+0x48]`) holds different bytes for
different connection origins: the real UniFi controller from
`10.1.1.1` gets `EXPECTED=3c232e92…`, the mock from `10.1.1.68`
gets `EXPECTED=1315740706…`, all in the same lorabrd process for the
same clientID. We don't yet know what selects the value.

| step | status |
|---|---|
| Mock controller active driver | ✅ implemented |
| 16-bit BE framing fix | ✅ verified live (TLS+WS+UBNT round-trip OK) |
| Unit tests for framing + state machine | ✅ 15 passing |
| `bridgeInfoGet` / `keyExchange` round-trip | ✅ live, response shape matches Y3 |
| Crypto chain (X25519 + BLAKE2b + secretbox) | ✅ verified — bridge's `secretbox_open` returns rc=0 with our ciphertext |
| `authorize.secret` content validation | ❌ blocked — bridge expects per-connection EXPECTED we can't derive |
| Phase 1 idle test (mock as sole controller) | 🟡 blocked on authorize |
| Phase 2 pair test (factory-reset sensor) | 🟡 blocked on Phase 1 |
| Phase 3 ACTIVE confirmation | 🟡 blocked on Phase 2 |

## Y4 findings (revised 2026-04-30) — crypto chain confirmed, EXPECTED is per-CONNECTION

The Y3 capture showed the bridge accepting random-looking 48-byte
base64 secrets, so we modeled `secret` as opaque session-state. That
was wrong. Live tests 2026-04-29 + 2026-04-30 with `secretbox_open`
and `memcmp` hooked in `lorabrd` revealed the full validation:

```
1. controller sends keyExchange.key = 32B X25519 pubkey
2. bridge generates ephemeral X25519 keypair, sends pubkey back
3. bridge does X25519(bridge_priv, ctl_pub) → shared
4. bridge derives:
       key = blake2b-32(shared || ctl_pub || bridge_pub || BRIDGE_SALT)
   where BRIDGE_SALT is a 32B per-clientID, **persistent across
   lorabrd restarts** value.
5. controller sends authorize.secret = base64(secretbox_easy(
       plaintext = AUTH_TOKEN,
       nonce     = ZEROS(20) || ASCII("UBNU"),
       key       = (4) above))
6. bridge runs sodium_base642bin → crypto_secretbox_open_easy →
   memcmp(decoded_PT, EXPECTED, 32). If equal → authorize ok.
```

For clientID `652ee9b0-8ea3-41a9-8589-b601159ea6b6`,
BRIDGE_SALT = `69b1d4a63a301106494473b25c23c372a1ba54fbbdbd4fd47ed638460e425f07`
(stable across lorabrd processes).

**Crypto chain confirmed working**: live test 2026-04-30 with the mock
producing the X25519 + BLAKE2b + secretbox chain → bridge's
`crypto_secretbox_open_easy` returns rc=0, decrypts to our chosen PT.
Only the memcmp against EXPECTED still fails (errorCode 4 "Bad secret").

### The 2026-04-29 doc was wrong about EXPECTED rotation

Earlier writeup claimed EXPECTED "regenerated per lorabrd process"
based on observing two distinct values across captures
(`3c232e92…` and `1315740706…`). The 2026-04-30 capture proves the
truth is more subtle: **EXPECTED is per-CONNECTION, not per-process**.

PID 384 (single lorabrd lifetime) capture, two memcmp events:
- mock connection from `10.1.1.68`: `A=1315740706…`, `B=3c232e92…` → mismatch
- real controller from `10.1.1.1`:   `A=3c232e92…`,   `B=3c232e92…` → match

Same lorabrd PID, same clientID, same client cert (lorabr.cert/key) —
**different bridge-side EXPECTED values**. Both controllers send the
SAME plaintext (`3c232e92…`), confirming that `3c232e92…` is the actual
shared AUTH_TOKEN. The puzzle is why the bridge's stored EXPECTED for
the mock connection was `1315740706…` instead.

### Data structure layout (Ghidra, FUN_0005f8b0)

The auth check is at `[param_1+4]+0x48`:
```c
FUN_0003bfa8(&local_b8, &local_e8, *(undefined4 *)(param_1 + 0x30), 0, &local_1c8);
pvVar7 = *(void **)(*(int *)(param_1 + 4) + 0x48);  // EXPECTED begin
__n    =  *(int *)(*(int *)(param_1 + 4) + 0x4c) - (int)pvVar7;  // size
if (... memcmp(pvVar7, local_b8, __n) != 0) { throw "Bad secret"; }
```

`param_1+4` points at an `auth_state` object; offsets 0x3c and 0x48
hold two `std::vector<uint8_t>` (begin/end/end_cap):
- `[+0x3c]` vector — **NEXT_SECRET** the bridge encrypts and sends
  to the controller (PT=`1315740706…` in the real-controller session)
  via the radio0 secret response path:
  ```c
  FUN_0003bf58(&local_1bc, *(int *)(param_1 + 4) + 0x3c, ...);
  // → secretbox(NEXT_SECRET, key, ZEROS+"UBNV") → base64
  // → {"iface":"radio0","secret":"<b64>"}
  ```
- `[+0x48]` vector — **EXPECTED** (the memcmp target)

Same KEY is used for both directions (decrypt UBNU / encrypt UBNV).

Heap dump of PID 3114 (real-controller session) confirmed both
vectors at `auth_state` base `0x16659c`:
```
+0x3c: 00145940  (begin OTHER) ─→  1315740706b7eb7f0eb925af76a805a5...
+0x40: 00145960  (end)
+0x44: 00145960  (end_cap)
+0x48: 00145b30  (begin EXPECTED) ─→  3c232e926c94efc66099574fa66ac4...
+0x4c: 00145b50  (end)
+0x50: 00145b50  (end_cap)
```

### What we ruled out for EXPECTED's source

- **Not** in `/etc/persistent/*` (binary + ASCII grep).
- **Not** in `/etc/avclient_state.json` (different schema, `authToken`
  field is for ubnt_avclient ↔ UniFi cloud auth on port 7442, not
  lorabrd's authorize.secret).
- **Not** in any other rootfs file (full filesystem grep negative).
- **Not** in lorabrd's BSS/data segment or any rw region of an idle
  lorabrd process — only appears when a connection is being
  authenticated, freed when connection closes.
- **Not** any obvious BLAKE2b/SHA-256 derivation of
  `authToken / BRIDGE_SALT / clientID / shared / ctl_pub / br_pub /
  session_key` or pairwise concatenations/HMACs (tested ~30 combos
  for both captured (ctl_pub, EXPECTED) pairs — none match).
- **Not** caught by libsodium hooks during the connection (no
  `randombytes`, `gh_*`, `scalarmult` produces it). The struct is
  populated **before the secretbox_open call** that yields the PT.
- **Not** triggered by `X-Mode: 0` header (real controller doesn't
  send it either; architecture doc was misleading).

### Open question: per-connection EXPECTED selection

What differs between the mock (`10.1.1.68`) and real controller
(`10.1.1.1`) connections that makes the bridge load different
EXPECTED bytes?

Same:
- clientID (`652ee9b0-8ea3-41a9-8589-b601159ea6b6`)
- mTLS cert (both present `lorabr.cert/lorabr.key`)
- Sec-WebSocket-Protocol: ucp4
- WS handshake otherwise

Different:
- Source IP / port
- SSL session ID (each connection fresh, no resumption)
- HTTP header order; mock sends `User-Agent: Python/3.14
  websockets/16.0`, real omits User-Agent

None of these obviously index into a different "slot" of stored
secrets, but something about the incoming connection identity must
select which 32-byte buffer goes into `auth_state[+0x48]`. Likely
candidates to investigate:

1. **`sub_5fdfc` callers** — what populates `auth_state` before
   FUN_0005f8b0 runs? Look at the WS handshake → ucp4 validate →
   first request handler chain.
2. **The `[+0x3c]` vs `[+0x48]` swap** — if the bridge has only ONE
   underlying value and mistakenly uses `+0x3c` (the
   "NEXT_SECRET-to-send") as `+0x48` (the memcmp target) for some
   connections, that'd explain why the mock got `1315740706…`. Check
   the constructor / setter functions for those vectors.
3. **OpenSSL hooks** — keyhook only catches libsodium. lorabrd uses
   libcrypto.so.3 for TLS; if EXPECTED is computed via libcrypto
   primitives (HMAC-SHA256, AES, etc.) we wouldn't see it.

## Path forward

Pragmatic options for a working open-gateway path:

1. **Static RE the auth_state initialization** (Ghidra) — find what
   writes `[auth_state+0x48]` and `[auth_state+0x3c]` per
   connection. xrefs to `0x5f8b0` (entry of FUN_0005f8b0) plus the
   constructor of the parser/connection-state object.
2. **Live extract via gdbserver** — break at `0x5fe14` (memcmp call),
   read `r0` as EXPECTED, send back via a side channel to the mock
   in real time. Race-y but doable.
3. **Patch lorabrd binary** — replace the `memcmp` with a constant
   `mov r0, #0; bx lr` to bypass the check. Heavy-handed but
   guarantees mock can authorize.
4. **Hook `open()/read()` in keyhook** — extend the LD_PRELOAD to
   trace every file read at lorabrd startup. If EXPECTED comes from
   a file (or `/dev/urandom` direct read), we'll see it.
5. **Hook `ubnt_avclient`'s SSL** — even though lorabrd has no Unix
   socket to ubnt_avclient, ubnt_avclient itself may push values
   into shared memory or a watched file. Worth a separate keyhook
   deployment on ubnt_avclient.

## What's confirmed working

- TLS + WS + UBNT framing (16-bit BE length prefix) round-trips
- bridgeInfoGet, keyExchange complete cleanly
- mock's X25519 + BLAKE2b session-key derivation produces the SAME
  key the bridge derives (verified: `secretbox_open` returns rc=0)
- `authorize.secret` = `base64(secretbox(AUTH_TOKEN, ZEROS+"UBNU", key))`
  decrypts cleanly on the bridge side
- The mock's hardcoded `AUTH_TOKEN=3c232e92…` IS the value the real
  UniFi controller sends (verified by capturing real controller's
  successful authorize → `secretbox_open` PT = `3c232e92…`)
- Bridge accepts mock connection (TLS, WS, ucp4 handshake all OK)
  ONLY when the real controller is firewalled — without firewall we
  get errorCode 12 "Duplicate connection" before crypto runs
- Bridge sends NEXT_SECRET response (encrypted with NONCE_tail="UBNV")
  AFTER successful authorize — the mock currently logs but ignores
  this response

## Methods used 2026-04-30

- Re-imported `lorabrd` into Ghidra 12.0.4 headlessly via
  `analyzeHeadless` with project at
  `firmware/analysis/up-sense-link/ghidra_project/lorabrd_proj`. Decomp
  output of FUN_0005f8b0 / FUN_0003bfa8 / FUN_0002ffb8 is in
  `/tmp/authorize_analysis.txt` (regenerate via
  `tools/ghidra_scripts/dump_authorize.py`).
- Used `ip route add blackhole 10.1.1.1/32` + `tcp_retries2=3` to
  briefly drop the real-controller connection so the mock could
  attempt authorize without the duplicate-clientID rejection.
  Restored both after the test.

## Phase 1 prerequisites — UPDATED

Live tests confirmed:

- TLS handshake + WS upgrade + mTLS work with `lorabr.cert/key`.
- 8-byte UBNT framing with **16-bit BE length** is correct.
- `bridgeInfoGet` returns the full bridge info (282-byte body —
  exercises the high byte of the 16-bit length).
- `keyExchange` round-trip works (ephemeral X25519 pubkey exchange).
- The bridge supports concurrent controller connections.
- The mock's `secretbox(AUTH_TOKEN, NONCE, KEY)` decrypts cleanly on
  the bridge side — the only thing wrong is the AUTH_TOKEN value.

The blocker is `authorize.secret`'s EXPECTED plaintext, not the
crypto chain. Don't repeat the firewall step until EXPECTED's source
is identified.

## What's ready

[`tools/mock_controller/server.py`](../../tools/mock_controller/server.py)
is now an active driver. On a fresh bridge connection it:

1. Bootstraps: `bridgeInfoGet` → `keyExchange` → `authorize` →
   `discoveryStart`. If `radio0.isReady=false` it raises and the connect
   loop reconnects after a back-off — same path the real controller
   takes (we observed `Interface down` errorCode 7 in Y3 conn1).
2. On `discoveryResult` events for a known sensor (MAC in
   `MockController.sensors`):
   - `adopted=false` → `addDevice` with the per-sensor persistent
     key, then immediately the captured 3-burst (0x53, 0x44, 0x74
     grant). NN counter starts at `0x9a` so the burst NNs land on
     `0x9a/0x9b/0x9c` matching the captured grant body's `NN=0x9c`
     and avoiding any patch of the authenticated payload.
   - `adopted=true` → mark sensor ACTIVE.
3. On `messageReceived` events:
   - `0x0a NN ...` (sensor 0x44 management UL) → reply with
     `0e NN+1 0d 00 01 2c` + `0b NN+2 11 01 0d 14`.
   - `0x03 NN ...` (66 B sensor grant ACK) → `removeDevice` then
     rotated `addDevice` (`aed56bd5… / a42b0887…`) then post-rotation
     burst `09 NN`, `0b NN+1 11 01 0d 14`, `09 NN+2`.
   - `0x0c …` telemetry → log only; no reply.

## Wire-format correction

The Y3 doc speculated about the 8-byte prefix's last byte being a
`type` code. Verified against the actual capture bytes that **the
last two bytes of the prefix are a 16-bit big-endian length**. The
short-body single-byte interpretation worked for everything observed
in idle but breaks immediately on the first long body (the
bridgeInfo response with caps is 282 bytes; its prefix is
`02 01 00 00 00 00 01 1a` — not a `type=0x1a`).

The prefix layout is:

```
01 01 00 00 00 00 LEN_HI LEN_LO    primary envelope
02 01 00 00 00 00 LEN_HI LEN_LO    secondary payload
```

This is now the framing in `encode_pair` / `decode_frame`.

## Open questions (carry-overs from Y3)

These remain unanswered until the live test runs. None block the Y4
implementation — they're things to look for during the test:

- **Will the sensor accept a replayed grant?** The Y3 grant body's
  64-byte middle is plausibly an X25519 ephemeral pubkey + Poly1305
  ciphertext (see Y3 doc analysis). If the sensor enforces freshness
  on the encrypted payload (e.g. session-id or timestamp inside the
  16 B plaintext), replay fails and we'll see the sensor silently
  retry the 0x43 challenge instead of moving to the 0x03 grant ACK.
- **Will the bridge accept multiple controllers simultaneously?**
  Y3 captures show two SSL pointers — implies yes — but only one
  controller appears to be issuing pair-affecting commands at a
  time. Concurrent `addDevice` from real + mock would fight. Phase 1
  firewall avoids this entirely.
- **Idle hold time without `addDevice`.** If we connect, bootstrap,
  and never send `addDevice`, does the bridge eventually drop us, or
  hold indefinitely? Phase 1 answers this.

## Phase 1 prerequisites (for live test)

The user must:

1. Block `10.1.1.1` (real controller) inbound on the bridge before
   the test. Suggested:

   ```bash
   ssh ubnt@10.1.1.141 "iptables -I INPUT -s 10.1.1.1 -p tcp --dport 8571 -j DROP"
   ```

   Reverse with `-D` after the test window.

2. Run the mock in active mode:

   ```bash
   /Users/alex/superlink/.venv/bin/python tools/mock_controller/server.py \
       --bridge 10.1.1.141:8571 --active -v --no-reconnect
   ```

3. Watch the mock's log for ≥ 3 minutes. Pass criteria:
   - Bootstrap completes (logs `✓ bootstrap complete`).
   - WS heartbeat ping/pong every ~80 s.
   - No `RuntimeError` from the radio-not-ready path.
   - No `connection error` from a peer-side close.
   - Bridge keeps the SSH session healthy (no kernel/lorabrd panic).

If those hold, proceed to Phase 2.

## Phase 2 — pair test

With the firewall still in place and the mock running:

1. Factory-reset the test sensor (`90:41:B2:2E:9A:53`).
2. Watch the mock's log for the captured event sequence:
   - `discoveryResult` events with `adopted=false` (every ~5 s).
   - First `addDevice` request from us → bridge ack.
   - 3-burst `sendMessage` requests `099a / 0b9b… / 029c…`.
   - `messageReceived` with body starting `0a 9a` (sensor 0x44
     management UL with NN echo).
   - Mock's `0e9d…` + `0b9e…` replies.
   - `messageReceived` with body starting `03 9c` (66 B grant ACK).
   - Mock's `removeDevice` + rotated `addDevice` + post-rotation
     burst `099f / 0ba0… / 09a1`.

If the sensor never sends the `0x03` grant ACK, the replay-grant
hypothesis is wrong; we'd see the bridge instead reissue the 0x43
challenge every ~34 s. In that case we go to Phase Y5 (compute our
own grant by ECDH against the sensor's static pubkey, which we'd
need to recover separately).

## Phase 3 — ACTIVE confirmation

Pass criteria:

- `discoveryResult adopted=true` event from the bridge.
- Periodic `messageReceived` events with body `0c …` (telemetry).
- Sensor's status LED reaches the steady state for "paired"
  (per the verify-before-success-claims rule, the LED is the source
  of truth — JSON-RPC events alone aren't conclusive).

## Deviations from Y3 to record

(To be filled in after the live tests.)
