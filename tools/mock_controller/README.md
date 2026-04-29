# Mock UniFi Controller

Replaces the UniFi Network controller in the bridge↔controller WebSocket
session so a real Ubiquiti `lorabrd` can drive sensor adoption/pairing
without the real controller.

This is Phase Y of the
[open-gateway plan](../../docs/OPEN_GATEWAY_PLAN.md). Ground-truth
schema lives in
[`docs/protocol/controller_y3_findings.md`](../../docs/protocol/controller_y3_findings.md).

## Setup

```bash
source .venv/bin/activate          # or use ../.venv on macOS
pip install 'websockets>=12'

# Passive run — connect, log RX, never drive any state. Useful as a smoke
# test for framing + WS handshake.
python tools/mock_controller/server.py --bridge 10.1.1.141:8571 -v

# Active run — bootstrap (bridgeInfoGet → keyExchange → authorize →
# discoveryStart) and drive a captured pair script in response to
# bridge events. Requires the real controller to be blocked first.
python tools/mock_controller/server.py --bridge 10.1.1.141:8571 --active -v
```

Traffic log written to `captures/live/mock_controller.jsonl`.

### Prerequisite: bridge client certs

The bridge requires mTLS. The mock needs a client cert + key the
bridge will trust. The bridge accepts its own `lorabr.cert` +
`lorabr.key` as a valid client credential (self-signed CN=localhost
trust pool).

Extract from a bridge you have SSH access to:

```bash
mkdir -p tools/mock_controller/bridge_certs
scp ubnt@<bridge-ip>:/etc/persistent/lorabr.cert \
    ubnt@<bridge-ip>:/etc/persistent/lorabr.key \
    tools/mock_controller/bridge_certs/
```

The `bridge_certs/` directory is gitignored — private keys should
not be committed.

## Wire format

Verified against `captures/live/y3/bridge_y3_pair_20260429.log`:

```
01 01 00 00 00 00 LEN_HI LEN_LO  <LEN-byte JSON envelope>
02 01 00 00 00 00 LEN_HI LEN_LO  <LEN-byte JSON payload>
```

- 8-byte prefix; first byte 0x01 = envelope, 0x02 = payload.
- `LEN` is **16-bit big-endian** (the earlier 1-byte interpretation
  was a coincidence of all observed bodies being ≤ 255 bytes).
- Each application message is one (envelope, payload) pair. Multiple
  pairs may be concatenated in a single WebSocket frame.
- The envelope's `"type"` field is the source of truth for
  `request` / `response` / `event` — not the prefix bytes.

WS-level: `Sec-WebSocket-Protocol: ucp4`, `permessage-deflate`
negotiated; observed frames in idle and pair were all uncompressed
(RSV1=0). Heartbeat is WS-level ping/pong with epoch-ms ASCII
payload — handled automatically by the websockets library.

## Active driver

Walks the captured Y3 factory-reset pair script:

1. **Bootstrap** — bridgeInfoGet → keyExchange → authorize →
   discoveryStart. If `radio0.isReady=false` we bail and reconnect
   with backoff (mirrors real controller behaviour).
2. **discoveryResult adopted=false** for a known sensor → send
   `addDevice` with the persistent per-sensor key, then immediately
   send the captured 3-burst:
   - 0x53 short reply `09 NN`
   - 0x44 management reply `0b NN+1 11 01 0d 14`
   - **0x74 grant** — captured 70-byte body, NN aligned to NN+2
3. **messageReceived 0x0a** (sensor 0x44 management UL) → reply with
   `0e NN 0d 00 01 2c` + `0b NN+1 11 01 0d 14`.
4. **messageReceived 0x03** (66B sensor grant ACK) → `removeDevice`
   then `addDevice` (rotated key + fallbackKey) then post-rotation
   burst (`09 NN`, `0b NN+1 11 01 0d 14`, `09 NN+2`).
5. **discoveryResult adopted=true** → mark sensor ACTIVE, log.

The default `--nn-start 0x9a` matches the captured Y3 NN sequence
exactly so the grant body's NN=0x9c lands on burst position 3 with
no patching of the authenticated payload.

## Sensor DB

Pre-seeded with the test sensor `90:41:B2:2E:9A:53`. Persistent and
rotated keys come from
[`docs/protocol/controller_y3_findings.md`](../../docs/protocol/controller_y3_findings.md).
Add more sensors to `TEST_SENSOR` / `MockController.sensors` as you
capture them.

## Tests

```bash
.venv/bin/python -m pytest tests/test_mock_controller.py -v
```

15 tests: framing round-trip, captured-bytes spot checks, and a
state-machine walk through the synthetic pair script. No bridge
required.

## Redirecting the bridge

The bridge connects out to `10.1.1.1:41522` for the controller. Three
ways to redirect to the mock at boot:

1. **DNAT on the upstream gateway** — redirect `bridge → 10.1.1.1:41522`
   to the mock host. Cleanest if you own the router.
2. **Isolated LAN** — put the bridge on a LAN segment where the mock
   answers to `10.1.1.1`.
3. **Binary patch** — edit the IP literal in `lorabrd`. Last resort.

For the *opposite* direction — connecting *into* the bridge as a
secondary controller without redirecting — the bridge accepts a
TLS WS *server* connection on port 8571 and handles multiple
controllers concurrently (different SSL pointers per connection).
The mock does this. Useful for read-only observation; not useful
for an exclusive Y4 pair test, which needs the real controller
firewalled off the bridge first.

## Phase Y4 test plan

See [`../../docs/OPEN_GATEWAY_PLAN.md`](../../docs/OPEN_GATEWAY_PLAN.md)
"Phase Y4". Three steps, each escalating in disruption to the user's
existing UniFi setup:

| step | action | risk |
|---|---|---|
| smoke | passive mode against bridge for 30s | none — second controller |
| idle | block real controller, run --active for ~3 min, observe | brief — sensor unreachable to real controller during test window |
| pair | factory-reset sensor with --active mock running | full — sensor's UniFi adoption replaced by mock |

Results to be recorded in
[`../../docs/protocol/controller_y4_results.md`](../../docs/protocol/controller_y4_results.md).
