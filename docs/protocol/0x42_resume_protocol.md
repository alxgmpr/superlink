# 0x42 Connection-message resume / reconnect (inner_type 0)

Reverse-engineered from `lorabrd` (Binary Ninja, 2026-07-31). Explains the
2-byte `01 00` frames on dctrl `0x42` the sensor sends mid-session that the
bridge previously dead-ended ("ConnectionChallenge too short"), stranding the
link in the stuck-resume loop.

## The connection-message dispatcher: `sub_524ac`

A received `0x42` connection message is parsed and dispatched on its
**inner_type** via a `switch`:

```
sub_524ac:
    ... "Got connection message [...]"
    switch (inner_type):
        case 0 -> sub_51914 -> sub_51742      # resume / reconnect
        case 2 -> sub_52090                    # full challenge ("New session")
```

Inner_type lives at wire offset `[1]` of the decrypted connection payload
(`01 02` = full Challenge, `01 00` = resume). `sub_439f0(obj, n)` stores `n`
as the inner_type field (`+0x1d`): 1 = ConnRsp, 2 = Challenge, 3 = ChallengeRsp.

## inner_type 0 = reconnect request → gateway answers with a ConnRsp

`sub_51742` (via `sub_51914`, which only length-checks and passes a flag):

- **Generates a fresh keypair** — `sub_3af20(obj+0x54)` = `randombytes_buf` +
  `crypto_scalarmult_base` (contrast the full-challenge path `sub_52090` which
  uses `sub_3af3c`).
- Builds a response and tags it **`sub_439f0(_, 1)` = inner_type 1 = ConnRsp**.
- Does **NOT** derive a session key (no `sub_3af5a`) — the session key is
  derived later, when the sensor replies with a Challenge (→ `sub_52090`).
- Refreshes a deadline (`+0x190/+0x194`, from `+0x30` seconds), re-emits the
  channel map (`+0x168` tree), and transmits via `sub_57ee8`.

So a short `01 00` on `0x42` is the sensor's **reconnect request**, and the
gateway answers it with a `0x62` ConnRsp — functionally identical to answering a
`0x40` discovery, just triggered on the connection channel instead of cold
discovery. The subsequent Challenge → ChallengeRsp → new-session flow is the
same as a fresh pair.

## Why the bridge got stuck

`bridge/session.py` ignored `0x42` entirely in ACTIVE and rejected the short
`0x42` as "too short" in BEACONING, so the reconnect request was never answered.
The sensor kept resending it (the 2-byte stuck-resume loop) until a watchdog
re-arm + physical nudge.

## Fix

`_handle_beaconing` now answers an inner_type-0 `0x42` with a `0x62` ConnRsp
(`_build_connrsp`, shared with the `0x40` path), respecting the reconnect-storm
backoff. The short-`0x42` tally still increments as a watchdog fallback. Lower
risk than the reverted "re-handshake on every 0x40 while ACTIVE" teardown loop:
we respond to the sensor's explicit reconnect request, we don't tear down a
healthy session spontaneously.

## Open / next

- ACTIVE fast-path: currently an in-ACTIVE `0x42` waits out the 60s link-lost
  timeout before the BEACONING handler answers the next resume. Answering in
  ACTIVE (drop → ConnRsp) would remove that gap but re-enters teardown-loop
  territory — add only with careful loop monitoring.
- The `0a 00 02` middle of the ConnRsp is copied from capture; `0a` is plausibly
  a random 0..63. The resume ConnRsp reuses the same hardcoded bytes and the
  current keypair (we do not regenerate, unlike the firmware — not required for
  interop as long as ConnRsp pubkey matches the DH key used for the session).
