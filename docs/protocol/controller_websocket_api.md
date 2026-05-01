# UniFi Controller ↔ Bridge WebSocket JSON-RPC API

Captured 2026-04-21 via LD_PRELOAD `send`/`recv` hook on the bridge
during factory-reset + adopt + pair cycle of USL-Entry sensor
`90:41:B2:2E:9A:53`.

This is the protocol between the UniFi controller (running on the
user's UDM / Network app) and the Ubiquiti SuperLink bridge. Replacing
the controller with a compatible mock is the path to an open-source
gateway (see [OPEN_GATEWAY_PLAN.md](../OPEN_GATEWAY_PLAN.md) Phase Y).

---

## Transport (verified 2026-04-21 via live mock-controller handshake)

- **Bridge is the WebSocket SERVER.** It listens on `0.0.0.0:8571`
  with TLS. The controller (or our mock) connects OUT to it.
  Earlier log references to `ws://10.1.1.1:41522` were the
  controller's ephemeral source port in the bridge's log output —
  the real listen port is `8571` on the bridge itself.
- **TLS**: the bridge presents a self-signed RSA-2048 server cert
  (CN=localhost) loaded from `/etc/persistent/lorabr.cert`. Peer
  verification on our side should be relaxed (CERT_NONE).
- **Client cert (mTLS)**: bridge REQUIRES a client cert. It
  validates against `/etc/persistent/controller.crt` (the real
  controller's cert) plus trusts self-signed CN=localhost certs.
  Empirically the bridge's own `lorabr.cert` + `lorabr.key` work
  as client credentials — the bridge accepts itself.
- **WebSocket version**: 13 (RFC 6455).
- **Extensions**: `permessage-deflate; client_max_window_bits`
  (both directions compressed once connected).
- **Subprotocol**: must offer `ucp4` in `Sec-WebSocket-Protocol`.
  The bridge selects it and responds with the same value in the
  101 response.
- **Required header**: `X-Mode: 0` (literal string "0"). Any other
  value causes the bridge to return `501 Not Implemented` with body
  "Only unencrypted mode is supported" in its log. Without the
  header the bridge returns `400 Bad Request`. The `"0"` is the
  literal token the bridge's validate-handler (`sub_64720`) looks
  for via `sub_2b97e(&var_d8, "0")` after splitting the header by
  whitespace.
- **Server banner**: `Server: UBNT-WS`.

### Minimum viable handshake (Python)

```python
import ssl, websockets
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.load_cert_chain("lorabr.cert", "lorabr.key")

async with websockets.connect(
    "wss://10.1.1.141:8571/",
    ssl=ctx,
    compression="deflate",
    subprotocols=["ucp4"],
    additional_headers={"X-Mode": "0"},
) as ws:
    ...  # JSON-RPC envelopes
```

---

## Envelope format

Each WebSocket text frame carries **two concatenated segments**:

1. **8-byte length/type framing prefix** (varies by message kind —
   structure not fully decoded yet, but starts with `01 01 00 00 00 00
   00` followed by a 1-byte ASCII code: `r` = response, `o` = event)
2. **JSON payload** (plain UTF-8 text, starts with `{`)

### Outer envelope (both request and response)

```json
{
  "id": "<uuid-v4>",
  "timestamp": <epoch_ms>,
  "type": "request" | "response" | "event"
}
```

Plus one of:

- `"method": "<method_name>"` (for requests — not observed from bridge
  in our captures, but the controller seems to expect them; probably
  deflate-compressed out of view)
- `"name": "<event_name>"` (for events — controller→bridge)
- `"error": "", "errorCode": 0` (for responses)
- `"result": {...}` or a second concatenated JSON blob (for responses
  with payload — sometimes the payload is a **separate JSON object**
  sent immediately after the envelope; see "Response body pattern"
  below)

### Response body pattern

Observed responses look like:

```
<framing prefix>r{"error":"","errorCode":0,"id":"...","timestamp":...,"type":"response"}<prefix>J{"<field>":"<value>"}
```

The response's "result" payload is a **separate 8-byte-framed JSON
object**. `J` = 0x4A may be the type code for "sub-object" or a length
prefix; pattern unconfirmed.

---

## Known events (controller → bridge)

All observed with `"type":"event"`.

### `discoveryResult`

Published whenever the bridge discovers a sensor via 0x40 discovery.
First emitted with `"adopted":false`; after successful adoption,
re-emitted with `"adopted":true`.

```json
{"id":"cee32f48-4b04-41b5-a528-0f674fc58120",
 "name":"discoveryResult",
 "timestamp":1776798680912,
 "type":"event"}
```

Body payload (second JSON):

```json
{
  "adopted": true,
  "mac": "90:41:B2:2E:9A:53",
  "networkId": 1167,
  "signal": {"rssi": -33, "snr": 9},
  "ssid": 44692
}
```

Notes:
- `networkId: 1167` = `0x048F` = the stable trailing 4 bytes of every
  70B Class B grant body. This is the UniFi "network" the sensor
  belongs to.
- `ssid: 44692` = `0xAE94` = the magic 2 bytes in every sensor's 0x44
  UL body at offset 2 (`0a NN ae 94 …`). SuperLink uses the LoRaWAN
  term "ssid" for what is effectively a network discriminator.

### `devsInfoChanged`

Published on sensor state changes — after 0x40 discovery, after
adoption, after session-key derivation, etc.

```json
{"id":"4ffa90d3-240b-4dfc-8dff-1c50d4fda880",
 "name":"devsInfoChanged",
 "timestamp":1776798xxx,
 "type":"event"}
```

Payload not fully captured (truncated at 2KB in hook). Likely
contains per-sensor state deltas: `adopted`, `mac`, `lastSeen`,
maybe `sessionKey`, etc.

### `messageReceived`

Published by the bridge to the controller whenever the sensor sends
an 0x54 data uplink. The decrypted sensor payload is forwarded as a
hex string.

```json
{"id":"b25d336d-f86e-4941-84c5-54514b0171eb",
 "name":"messageReceived",
 "timestamp":1776798710129,
 "type":"event"}
```

Body:

```json
{
  "data": "0CA1010000000008110000010001000000F5A9470D00012C140000",
  "mac": "90:41:B2:2E:9A:53",
  "signal": {"rssi": -35, "snr": 8}
}
```

Notes:
- `data` is the **decrypted sensor UL body** as uppercase hex.
- Sensor 0x54 payloads appear to be a TLV structure beginning with
  `0C` (type) + 1-byte sensor counter (echoes last-received DL
  counter).
- This is the channel we'll use to expose events to MQTT / HA in the
  final open gateway.

---

## Known responses (controller → bridge, matched to requests)

### `"key"` field response

```json
{"key": "<64-char-uppercase-hex = 32-byte value>"}
```

Observed twice per boot (two separate IDs). Two different values
captured in pair6:
- `383B624F74372E325386FA529C3A62DC0573A0FA04CC4658EDE3C55D3130D315`
- `351DB21A9346020ABD8C90D2B390C3D48F255E57C075C357873593A42F724B7B`

The second one was confirmed to be used as the 4th input to
BLAKE2b-32 session-key derivation (alongside shared secret, gw_pub,
sensor_pub) at `gh_init → gh_update(32B) × 4 → gh_final(32B)`.

The first is a **separate** bridge-level key — possibly the inner
pairing key the bridge uses for `0x40` / `0x62` discovery frames. Not
yet confirmed.

### `"secret"` field response (base64)

```json
{"iface": "radio0", "secret": "89lFNDa1DU7vCrg5Ob6/DRkD0aKO3H4QolZB0GNfed9K02gaO+QDc48sL6kYQHal"}
```

48-byte base64-encoded secret for the `radio0` interface. Likely a
long-term auth key between bridge and controller (possibly the mTLS
session secret or a derived auth token).

### Error responses

```json
{"error": "Data exchange aborted with LoRa device",
 "errorCode": 15,
 "id": "...", "timestamp": ..., "type": "response"}
```

```json
{"error": "Interface down",
 "errorCode": 7,
 "id": "...", "timestamp": ..., "type": "response"}
```

---

## Known methods (bridge → controller, names inferred from strings)

These string names appear in the lorabrd binary as method identifiers
the bridge CALLS on the controller. Outbound requests are
deflate-compressed so we haven't decoded the full JSON yet, but the
names are visible in the binary:

- `startSessionKeyRenewal` — observed mid-pairing. Bridge probably
  requests the session-key material from the controller for a
  specific sensor.
- (others likely: `getDeviceKey`, `getDeviceSecret`, `adoptDevice`,
  `onDeviceDiscovered`, `onMessageReceived` — need binary RE or
  decompression capture to confirm)

---

## Known constants from captures

| Value | Meaning | Source |
|-------|---------|--------|
| `c5923a86…bd38db` | `keypair+0x30` context for sensor `9041b22e9a53` | controller, constant across sessions |
| `47be3dff…045c2dbe` | Ubi factory default "outer pairing key" | hardcoded in sensor firmware |
| `networkId: 1167` (0x048F) | UniFi network ID | controller, per-install |
| `ssid: 44692` (0xAE94) | LoRa network identifier | controller, per-install |
| `radio0` | Bridge radio interface name | bridge-local |

---

## For the mock controller

Minimum requirements to impersonate the controller enough for a
single bridge to pair a single sensor:

1. Accept WebSocket connection + handshake on `:41522` (permessage-
   deflate enabled).
2. Accept the bridge's inbound JSON-RPC requests (we'll log them;
   need to decompress deflate first).
3. Respond to `startSessionKeyRenewal` (and related) with canned
   `{"key": "<32B-hex>"}` responses. The `key` values can be copied
   from our captures for a known sensor, or freshly generated if
   pairing a new sensor.
4. Emit `discoveryResult` events with `adopted: true`, a chosen
   `networkId`, `ssid`, and the sensor's MAC once the bridge reports
   the sensor via its own outbound event.
5. Respond to `messageReceived` events (or acknowledge them) — the
   bridge expects reply envelopes.
6. Provide the `radio0` `secret` value so the bridge's interface stays
   "up".

The mock does NOT need to:
- Forge LoRa-side session crypto — the bridge derives the LoRa session
  key locally (BLAKE2b over its own DH with the sensor + the
  controller-supplied `addDevice.key`), MICs and XSalsa20-encrypts
  outgoing LoRa frames itself.
- Understand LoRa framing — only JSON.

The mock **does** need to forge the **inner Class B grant** (the 70 B
hex blob the controller pushes via `sendMessage.data` for `0x74` DL
replies). That body's 64-byte middle is computed by the UniFi
controller from per-sensor state — see
[controller_y3_findings.md](controller_y3_findings.md) and
[../OPEN_GATEWAY_PLAN.md](../OPEN_GATEWAY_PLAN.md) Phase Y5. As of
2026-04-30 the algorithm is unknown; the captured Y3 grant
replays at the LoRa layer (sensor sends 0x03 ACK) but fails at the
sensor's adoption layer (red LED, no `0x0c` telemetry).

The cleanest implementation is a Python `websockets`-based server +
a state machine that drives the pair flow. Starting point:
`tools/mock_controller/` (to be created).
