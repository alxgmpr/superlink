# Mock UniFi Controller

Replaces the UniFi controller's WebSocket endpoint at
`ws://10.1.1.1:41522` so an existing Ubi `lorabrd` binary can drive
sensor adoption/pairing without depending on the real controller.

This is Phase Y of the
[open-gateway plan](../../docs/OPEN_GATEWAY_PLAN.md). See also
[`docs/protocol/controller_websocket_api.md`](../../docs/protocol/controller_websocket_api.md)
for the captured JSON-RPC schema.

## Setup

```bash
source .venv/bin/activate
pip install 'websockets>=12'
python tools/mock_controller/server.py --bridge 10.1.1.141:8571 -v
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

## Redirecting the bridge

The bridge hardcodes `10.1.1.1:41522` as the controller endpoint. Three
ways to make it connect to the mock:

1. **DNAT on the upstream gateway** — redirect bridge→10.1.1.1:41522 to
   the machine running the mock. Cleanest if you own the router.
2. **Isolated LAN** — put the bridge on a LAN segment where the mock
   answers to `10.1.1.1` (static IP on the mock host).
3. **Binary patch** — edit the IP literal in `lorabrd`. Last resort.

## Status (Phase Y1)

What works:

- Accepts WebSocket handshake on port 41522 with permessage-deflate.
- Logs all inbound frames (hex + decoded JSON if present).
- Best-effort framing-prefix splitter (8-byte prefix + 1-byte type +
  JSON object). Multiple objects per WS frame are handled.
- Canned responses for `getDeviceKey` / `startSessionKeyRenewal` and
  `getInterfaceSecret` using values captured from the real controller.

What's next (Y2–Y3):

- Observe which method names the bridge actually calls (the outbound
  JSON is deflate-compressed, so we need the WebSocket library to
  decompress and then our parser to extract method names).
- Emit `discoveryResult` events when the bridge reports a new sensor.
- Emit `devsInfoChanged` after adoption.
- Track per-sensor state in the mock so repeated pair cycles work.

## Sensor DB

Pre-seeded with the test sensor `90:41:B2:2E:9A:53` and its per-device
`keypair+0x30` context. Add more sensors to `MockController.SENSOR_DB`
in `server.py` as you capture them, or have the mock generate random
keys for unknown MACs (less interoperable but useful for testing).
