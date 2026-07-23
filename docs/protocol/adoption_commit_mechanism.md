# SuperLink adoption-commit mechanism (ground truth)

Recovered 2026-07-22 by decoding `captures/live/bridge_adopt_fresh_pass2_20260722.log`
at BOTH layers the keyhook captures:
- **controller↔bridge JSON-RPC** (the WS `SSL_read`/`SSL_write` frames — plaintext
  JSON here, not permessage-deflate, so directly readable), and
- **LoRa plaintext** (the libsodium `FUNC=stream` `PHASE=pre/post` blocks, whose
  `KEY=` field is the exact XSalsa20 key used for each on-air frame).

Annotated interleaved transcript: `captures/live/bridge_adopt_fresh_pass2_DECODED.txt`.
Controller source: UniFi Protect `service.js` (UNVR fw 5.0.16), modules
`deviceAdopt.ts` (31048), `deviceConnection.ts` (15830), `bridgeRequest.ts`
(71804), `constants.ts` (62701), `messages.ts` (41118).

## Two constants that reframe everything

- **`LORA_DEVICE_DEFAULT_ADOPTION_KEY = c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db`**
  is a **global constant** in Protect (`constants.ts`), NOT a per-device secret.
  Every unadopted sensor and the controller use it as the pre-adoption session-KDF
  context. It "survives factory reset" simply because it is the default. Prior RE
  mislabelled it a "per-device factory key."
- **`LORA_BRIDGE_SALT`** (64B) and **`LORA_BRIDGE_NONCE`** = `00…00 55424e55` ("UBNU")
  are the controller↔bridge WS auth constants (`authorize.secret` path), unrelated
  to the sensor adoption.
- Pairing key `47be3dffb41ea3…` is the fixed default used to encrypt `0x40`
  discovery (always) and the pre-adoption `0x62/0x42` connect handshake.

## `deviceAdopt.ts` — the controller's adopt routine (no ratchet)

```
r = randomBytes(32); o = randomBytes(32)          // fresh random, per adoption
connectDevice(nvr, dev)                            // handshake under DEFAULT key
resp = request(ADOPT_REQUEST {gatewayPublicKey: base*r,
                              gatewayFallbackPublicKey: base*o,
                              networkId: getShortConsoleId(nvr)})   // 0x048f
m = E(r, resp.devicePublicKey)                     // addDevice.key      (primary)
h = E(o, resp.deviceFallbackPublicKey)             // addDevice.fallbackKey
y = hex(m) + hex(h)                                // 64-byte credential string
wait(1000)
connectDevice(nvr, dev, y)                         // RECONNECT under new keys
request(DEVICE_INFO_REQUEST); applyDeviceDefaults(); setDeviceConnected()
```

`E(priv, pub) = blake2b32( X25519(priv,pub) || base*priv || pub || H )`,
`H = 70be6851…c8970a59`. Our `adopt.py:kdf_E(r, dev_pub)` is **byte-identical**
(`shared || gw_pub || dev_pub || H`). Because the sensor derives the same value by
ECDH symmetry, **key mismatch is not the blocker** and there is **no rotation
counter / ratchet** to validate — the ADOPT ephemerals are pure random.

`connectDevice(nvr, dev, cred)` (`deviceConnection.ts`) tears down then re-adds at
the bridge JSON-RPC layer: `removeDevice{mac}` then
`addDevice{mac, key: cred[0:64], fallbackKey: cred[64:]}`. Pre-adoption `cred` is
empty so `key = LORA_DEVICE_DEFAULT_ADOPTION_KEY`, no fallbackKey.

## Observed command sequence for a successful adoption

| # | controller→bridge | effect |
|---|---|---|
| 1 | `sendMessage 0735` | FACTORY_RESET the sensor over LoRa ("forget device") |
| 2 | `removeDevice{mac}` | sensor drops to unadopted discovery (~24s of `adopted:false`) |
| 3 | `addDevice{key: c5923a86…}` | register DEFAULT key so the pre-adoption handshake works |
| 4 | `sendMessage 0236…0000048f` | ADOPT_REQUEST |
| 5 | *(recv)* `0336…` | ADOPT_RESPONSE (device pubkeys) |
| 6 | `removeDevice{mac}` | tear down the default-key session |
| 7 | `addDevice{key: 0fc32086…, fallbackKey: d704a818…}` | register the derived keys |
| 8 | `sendMessage 0937` | DEVICE_INFO_REQUEST (queued until reconnect) |
| — | *(event)* `discoveryResult{adopted:true}` | **COMMITTED** |

There is **no dedicated "confirm" LoRa message**. The `0x63 0100` seen on-air right
before commit is the MAC-layer ACK of the sensor's `0x54` ADOPT_RESPONSE data frame.

## Dual-key on-air model (the part our gateway gets wrong)

Reading the `KEY=` column of the LoRa stream ops across the adoption:

| frame | pre-adoption transport key | post-adoption transport key |
|---|---|---|
| `0x40` discovery | pairing `47be3dff…` | pairing `47be3dff…` (unchanged) |
| `0x62`/`0x42` connect handshake | pairing `47be3dff…` | **fallbackKey `d704a818…`** |
| operational app frames (`0x53/0x74/0x54/0x44/0x63`) | session key, KDF ctx = `c5923a86` (default) | session key, KDF ctx = **primary** `0fc32086…` |

So the two derived keys play different roles:
- **primary `addDevice.key`** → KDF *context* for `derive_session_key`
  (`blake2b32(shared||gw_pub||sensor_pub||ctx)`); never used directly as an
  on-air cipher key.
- **`fallbackKey`** → the XSalsa20 *transport* key that encrypts the post-adoption
  `0x62/0x42` reconnect handshake, replacing the pairing key in that role.

Verified from the full 32-byte `KEY=` values: frames 48–59 (the post-commit
reconnect handshake) use `d704a818b06d585076274149dd972b5740698e139cd781f61769189b5c69557d`,
which is exactly the `addDevice.fallbackKey` the controller registered in step 7.

## Consequences for `superlink-gw`

`gateway.py` uses `self.pairing_key` for every `0x40/0x62/0x42/ChallengeRsp`
frame (lines 434, 467, 479, 583). Correct pre-adoption; wrong post-adoption:

1. **Reconnect transport key (proven bug).** After commit the sensor's
   `0x62/0x42` frames are XSalsa20'd with the fallbackKey. The gateway decrypts
   them with the pairing key → garbage → the operational reconnect can never
   complete. Fix: after adoption, use `_derived_addDevice_fb_key` as the transport
   key for `0x62/0x42` (keep `pairing_key` for `0x40`, keep primary key as the
   session KDF context via `_kdf_context`).
2. **Conditional rotation.** Rotating `_kdf_context`/transport permanently on the
   ADOPT round-trip locks the gateway out if the sensor doesn't commit (it goes
   back to pairing-key handshakes). Rotation should trigger only on observing the
   adopted-form discovery `01ae94 8N 0000048f`.
3. **Open (needs bench).** The prior symptom is "sensor never emits adopted-form
   `0x40`," which is *upstream* of the reconnect. Candidate: our `0x63` ACK of the
   ADOPT_RESPONSE has wrong MAC framing/sequence so the sensor treats its
   ADOPT_RESPONSE as undelivered, times out ~24s, and reverts without committing.
   Next step: keyhook-decode our own failed attempt and diff the
   `0x53/0x74/0x54/0x63` counters and the `0x63` MIC against the DECODED
   transcript, frame for frame.
