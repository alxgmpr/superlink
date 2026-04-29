# Controller WebSocket — Y4 mock-driven pair results

Phase Y4 of the [open-gateway plan](../OPEN_GATEWAY_PLAN.md). Goal:
drive a real Ubiquiti SuperLink bridge through a complete sensor pair
using our mock controller, replaying the captured Y3 script.

## Status

**Implementation complete, framing verified live, but Phase 1 blocked
on `authorize.secret` content validation.** The bridge runs
`crypto_secretbox_open_easy` over the base64-decoded secret with
key/nonce we can't yet derive statically — every random / replayed /
hypothesised secret returns errorCode 4 "Bad secret".

| step | status |
|---|---|
| Mock controller active driver | ✅ implemented |
| 16-bit BE framing fix | ✅ verified live (TLS+WS+UBNT round-trip OK) |
| Unit tests for framing + state machine | ✅ 15 passing |
| `bridgeInfoGet` / `keyExchange` round-trip | ✅ live, response shape matches Y3 |
| `authorize.secret` validation | ❌ **NEW BLOCKER** — secret is content-validated, format unknown |
| Phase 1 idle test (mock as sole controller) | 🟡 blocked on authorize |
| Phase 2 pair test (factory-reset sensor) | 🟡 blocked on Phase 1 |
| Phase 3 ACTIVE confirmation | 🟡 blocked on Phase 2 |

## NEW Y4 findings — authorize.secret crypto cracked, EXPECTED still unknown

The Y3 capture showed the bridge accepting random-looking 48-byte
base64 secrets, so we modeled `secret` as opaque session-state. That
was wrong. Live test 2026-04-29 with `crypto_secretbox_open_easy` and
`memcmp` hooked in `lorabrd` revealed the full validation:

```
1. controller sends keyExchange.key = 32B X25519 pubkey
2. bridge generates ephemeral X25519 keypair, sends pubkey back
3. bridge does X25519(bridge_priv, ctl_pub) → shared
4. bridge derives:
       key = blake2b-32(shared || ctl_pub || bridge_pub || BRIDGE_SALT)
   where BRIDGE_SALT is a 32B per-clientID, **persistent across
   lorabrd restarts** value (we don't yet know its source).
5. controller sends authorize.secret = base64(secretbox_easy(
       plaintext = AUTH_TOKEN,
       nonce     = ZEROS(20) || ASCII("UBNU"),
       key       = (4) above))
6. bridge runs sodium_base642bin → crypto_secretbox_open_easy →
   memcmp(decoded_PT, EXPECTED, 32). If equal → authorize ok.
```

Captured live for clientID `652ee9b0-8ea3-41a9-8589-b601159ea6b6`:
- BRIDGE_SALT = `69b1d4a63a301106494473b25c23c372a1ba54fbbdbd4fd47ed638460e425f07`
  (stable across two separate lorabrd processes — persistent state).
- EXPECTED = `1315740706b7eb7f0eb925af76a805a5c9dd6912836680acaefff77e27f8e3ae`
  for the latest lorabrd process. **EXPECTED differs** between
  processes — `3c232e926c94efc66099574fa66ac41cb414971d0f0d744b29f1e2b21ea61f50`
  in an earlier capture. Regenerated per-process.

So the mock can now produce a secret that **decrypts cleanly** on the
bridge side (the `crypto_secretbox_open_easy` returns rc=0). What it
can't do is produce a plaintext that matches the bridge's per-process
EXPECTED — every test ended at `memcmp` returning non-zero with our
plaintext (3c232e92…) versus the bridge's EXPECTED (13157407…).

EXPECTED isn't:
- In `/etc/persistent/*` (grep'd both ASCII and hex).
- In the heap of a fresh hooked `lorabrd` (dumped 0x10a000–0x179000).
- The bridge's `authToken` from `ubnt_avclient.conf`, or any
  obvious BLAKE2b/SHA derivation thereof.
- Captured in keyhook events (no `randombytes`, `gh_*`, or other
  hooked symbol produces it during the connection — meaning it
  exists *before* we observe it).

That last bullet is the key clue: EXPECTED is a per-clientID secret
that the bridge **already has** by the time the controller's authorize
arrives. Source candidates:

1. **avclient adoption sync** — when ubnt_avclient (port 7442 to
   UniFi cloud) adopts the bridge, the cloud may push a per-controller
   EXPECTED token into bridge memory via a different protocol that
   `lorabrd` then reads.
2. **Cross-process IPC** — `lorabrd` reads the value from `ubnt_avclient`
   on demand (via Unix socket / shared memory).
3. **Derivation from a longer-lived bridge secret** that we haven't
   inspected yet (dropbear host key? mTLS private key bytes?).

## Path forward

Two productive next moves:

1. **Hook `lorabrd`'s `r4[#4][#72]` access** (the std::string holding
   EXPECTED, accessed at `0x5fe02`). Either:
   - Add an `mprotect`-based watchpoint via gdbserver on that address.
   - Hook the std::string allocator and log every 32-byte
     allocation tagged with caller RA — find the path that fills
     EXPECTED.
2. **Hook `ubnt_avclient`** in the same way — if it provides EXPECTED
   to lorabrd via IPC, the call chain is observable.

Until EXPECTED is known, the mock controller blocks at `authorize`
with `errorCode 4 "Bad secret"`. The mock IS now correctly
performing the crypto chain (verified end-to-end via keyhook); only
the EXPECTED plaintext is wrong.

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
