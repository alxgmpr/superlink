# SuperLink LoRa application-layer protocol

Recovered 2026-04-30 from static RE of UniFi Protect bundle inside
UNVR firmware v5.0.16
(`firmware/analysis/unvr-5.0.16/ulp-fs/usr/share/unifi-protect/app/service.js`,
webpack module `41118` =
`./src/middleware/devices/loraBridges/helpers/applicationLayer/messages.ts`).

This doc supersedes the speculative "Class B grant" interpretation in
[`controller_y3_findings.md`](controller_y3_findings.md) "64B
grant-middle structure". The 70-byte body the controller pushes via
`sendMessage.data` is **plaintext** — there is no inner encryption.

## Wire framing (recap)

Application-layer messages travel as the body inside LoRa MAC frames
between bridge and sensor. The bridge's outer LoRa-frame layer
(BLAKE2b-32 4B MIC + XSalsa20 with the LoRa session key) wraps the
whole body; that's the *only* crypto applied. Once the LoRa-layer
is decrypted, what's left is the message described below.

In the controller↔bridge JSON-RPC, the controller pushes outgoing
application messages as hex in `sendMessage.data` and the bridge
delivers incoming messages as hex in `messageReceived.data`.

## Message envelope

Every message:

```
offset  size  field
0       1     messageId    (uint8, see MessageId table)
1       1     messageTag   (uint8, request/response correlator)
2..     N     payload      (per-messageId encoding)
```

Maximum payload size is enforced to a constant `s` (we haven't
extracted the value from the bundle but encode/decode both check
it).

## MessageId enum (full, from messages.ts)

| value | name                      | direction       |
|-------|---------------------------|-----------------|
| 1     | `REQUEST_STATUS_RESPONSE` | device → ctl    |
| 2     | `ADOPT_REQUEST`           | ctl → device    |
| 3     | `ADOPT_RESPONSE`          | device → ctl    |
| 4     | `PING_REQUEST`            | ctl → device    |
| 5     | `PING_RESPONSE`           | device → ctl    |
| 6     | `REBOOT`                  | ctl → device    |
| 7     | `FACTORY_RESET`           | ctl → device    |
| 8     | `LOCATE`                  | ctl → device    |
| 9     | `DEVICE_INFO_REQUEST`     | ctl → device    |
| (cont)| `DEVICE_INFO_REPORT`      | device → ctl    |
| (cont)| `PROPERTY_REQUEST`        | ctl → device    |
| (cont)| `PROPERTY_REPORT`         | device → ctl    |
| (cont)| `PROPERTY_SET`            | ctl → device    |
| (cont)| `FIRMWARE_UPDATE_START`   | ctl → device    |
| (cont)| `FIRMWARE_CHUNK_REQUEST`  | device → ctl    |
| (cont)| `FIRMWARE_CHUNK_RESPONSE` | ctl → device    |

(Numeric values for the second-page entries are sequential after 9.
TODO when the implementation needs them — extract directly from
`service.js` module 41118.)

## Per-message encodings

### `ADOPT_REQUEST` (messageId 2) — formerly mis-called the "Class B grant"

Total wire size **70 bytes**.

```
0       1     messageId = 0x02
1       1     messageTag (rolling counter)
2       32    gatewayPublicKey            (Curve25519 u-coord, LE)
34      32    gatewayFallbackPublicKey    (Curve25519 u-coord, LE)
66      4     networkId                   (uint32 BE — short console id)
```

Both pubkeys are fresh ephemeral keys generated per pair attempt by
the controller. `networkId` is the controller's short console id
(`getShortConsoleId(nvr)` in the source); for the test environment
it's `0x048F = 1167`.

The Y3 capture's grant body decoded:

```
02 9c
4b144c10e0703533e445b8cbeffc3d98704bbc873ba68b13a86269b7b2cd4378  ← gatewayPublicKey
cf15f1b061326f8e2c5ed91dc3b54e147696679e968d7d136df7561f02989b2b  ← gatewayFallbackPublicKey
00 00 04 8f                                                       ← networkId 1167
```

### `ADOPT_RESPONSE` (messageId 3)

Total wire size **66 bytes**.

```
0       1     messageId = 0x03
1       1     messageTag (echoes request)
2       32    devicePublicKey             (Curve25519 u-coord, LE)
34      32    deviceFallbackPublicKey     (Curve25519 u-coord, LE)
```

The Y3 capture's 0x03 sensor reply decoded:

```
03 9C
8F0F12DE419E0D8DB5D7ABD8AAB7A6B5037C0BE13C984BC8C93AE75C1438A120  ← devicePublicKey
EF9A96027A8B842113C6F75D7F3F6107A531275B359A2DD107478DFAAC0EAC06  ← deviceFallbackPublicKey
```

### `REQUEST_STATUS_RESPONSE` (messageId 1)

3 bytes total. Sent by device when it can't process a request:

```
0       1     messageId = 0x01
1       1     messageTag
2       1     statusCode
```

### `PING_REQUEST` / `PING_RESPONSE` (4/5)

Variable. 2-byte header + opaque `data: Buffer`. Used for liveness.

### `REBOOT` / `FACTORY_RESET` / `LOCATE` / `DEVICE_INFO_REQUEST` (6–9)

Header only — 2 bytes, no payload.

`FACTORY_RESET` unpairs the device. The messageTag MUST be non-zero — a `0700`
body is silently ignored (no ACK, no reset; verified on hardware 2026-07-25).

The sensor confirms with a `REQUEST_STATUS_RESPONSE` (msgId 1) echoing the
command's tag, in a **later window** than the command itself:

    DL dctrl=74  body=0735      FACTORY_RESET, tag 0x35
    DL dctrl=54  ...
    UL dctrl=54  body=013500    REQUEST_STATUS_RESPONSE, tag 0x35, status 0

The controller removes the device from its registry only after that status
(`captures/live/bridge_adopt_fresh_pass2_DECODED.txt`, JSON 11 `removeDevice`).
superlink2mqtt mirrors this: `BridgeCore` deletes the record and emits
`DeviceRemoved` on a tag-matched status 0, and does nothing on a mismatch or a
non-zero status — except that a non-zero status also clears the pending-reset
entry for that tag, so a later status that somehow still confirmed the same
reset would no longer be recognized. After the reset the sensor beacons again
as unadopted and can be re-paired normally.

### `DEVICE_INFO_REPORT`

Variable, ≥31 bytes. Layout (from decodeMessage):

```
0       1     messageId
1       1     messageTag
2       2     deviceType         (uint16 BE)
4       2     fwVersionMajor
6       2     fwVersionMinor
8       2     fwVersionPatch
10      4     fwBuildId          (hex string of uint32 BE)
14      1     hardwareRevision
15      16    anonymousDeviceId  (16-byte device-unique blob)
31      1     supportedMessageIds.count = N
32      N     supportedMessageIds[]
32+N    1     supportedProperties.count = M
33+N   3*M    supportedProperties[]: { propertyId:1, channelCount:1, valueSize:1 }
```

### `PROPERTY_REQUEST`

```
0       1     messageId
1       1     messageTag
2       N     propertyId[] (one byte each, N=number of properties to query)
```

### `PROPERTY_REPORT` / `PROPERTY_SET`

Sequence of property entries:

```
each entry: propertyId:1, channel:1
            then either fixed-size value (size from device's
            wirelessConnectionSettings.loraPropertySizes[propertyId])
            or dynamic: length:1 || value:length
```

Decoder requires `device.wirelessConnectionSettings.loraPropertySizes`
to disambiguate fixed vs dynamic per property.

### `FIRMWARE_UPDATE_START`

```
0       1     messageId
1       1     messageTag
2       4     size               (uint32 BE — total firmware size)
```

### `FIRMWARE_CHUNK_REQUEST` (device → ctl)

```
0       1     messageId
1       1     messageTag
2       4     size
6       4     offset
10      1     status
```

### `FIRMWARE_CHUNK_RESPONSE` (ctl → device)

```
0       1     messageId
1       1     messageTag
2       4     offset
6       N     firmwareChunk
```

## Controller-side persistent-key derivation

Recovered from
`./src/middleware/devices/loraBridges/subscribers/deviceAdopt.ts`
(webpack cluster around bundle offset 4 064 734).

```python
H = bytes.fromhex(
    "70be68514ce7b81328d9f3215855c5675336ea88a08a728df7fce95cc8970a59"
)

def E(my_priv: bytes, their_pub: bytes) -> bytes:
    """ blake2b-32(X25519(my_priv, their_pub) || base*my_priv ||
                   their_pub || H) """
    shared  = scalarmult(my_priv, their_pub)        # 32 B
    my_pub  = scalarmult_base(my_priv)              # 32 B
    return blake2b(shared + my_pub + their_pub + H, digest_size=32)
```

After receiving the sensor's `ADOPT_RESPONSE`, the controller
derives:

```python
addDevice_key          = E(r, devicePublicKey)
addDevice_fallbackKey  = E(o, deviceFallbackPublicKey)
```

where `r` and `o` are the ephemeral private keys the controller
generated for the just-sent `ADOPT_REQUEST`. The sensor performs the
inverse with its own fresh ephemeral privates, so both sides hold
identical `(addDevice_key, addDevice_fallbackKey)` pairs after the
exchange.

These become the per-sensor persistent secrets. They feed the
bridge's session-key KDF as the 4th input
(`blake2b(shared || pub_a || pub_b || addDevice.key)`, see
[`controller_y3_findings.md`](controller_y3_findings.md)
"Session-key KDF — fully confirmed").

Each subsequent re-pair runs another ADOPT_REQUEST/RESPONSE cycle
and **rotates** these values. In the Y3 trace this is the
post-grant `removeDevice` + `addDevice {key=aed56bd5…,
fallbackKey=a42b0887…}` step.

## Open questions

1. Numeric values for `DEVICE_INFO_REPORT`, `PROPERTY_*`,
   `FIRMWARE_*` MessageId entries — easily extracted from
   service.js when needed.
2. Maximum payload size constant `s` in encodeMessage.
3. Where in the controller's per-sensor record the
   `addDevice_fallbackKey` is stored (we observed it in some
   `addDevice` calls but not others).
4. The `anonymousDeviceId` field in DEVICE_INFO_REPORT — likely
   the sensor identity blob the controller mixes into the
   bridge↔controller WS session-key KDF (already documented;
   here we have its source).
