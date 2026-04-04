# SuperLink Frame Format

## Overview (from lorabrd decompilation)

All fields are **big-endian**. The frame structure has two layers:
a LoRa PHY payload wrapper, and inner protocol messages.

## PHY Payload Frame

From the size constants and parsing functions in lorabrd:

```
Offset  Size  Field              Notes
------  ----  -----              -----
0       10    Cleartext Header   Always unencrypted, prefix for all frames
10      4     Integrity Check    BLAKE2b truncated to 4 bytes (covers header + payload)
14      N     Payload            Encrypted with XSalsa20 for SecureHeader,
                                 or plaintext for PlainHeader
```

**Total minimum frame size: 14 bytes** (`FUN_00043790` returns 0x0E)

### Cleartext Header (10 bytes)

From `FUN_00043788` = 10 bytes, and the `phypayload::Header` structure:

```
Offset  Size  Field     Type                 Notes
------  ----  -----     ----                 -----
0       1     Mctrl     uint8_t              Management/message control byte
1       1     Dctrl     uint8_t              Data control byte
2       6     Address   MacAddress (6 bytes)  Source or destination MAC
8       1     SeqHi     uint8_t              Frame counter (monotonically increasing)
9       1     SeqLo     uint8_t              Nonce/sub-counter (varies per frame)
```

The Mctrl and Dctrl bytes are bitfield structures (classes `phypayload::Mctrl`
and `phypayload::Dctrl`). Their exact bit layout needs further RE.

#### Observed Mctrl values

| Value | Binary     | Context |
|-------|-----------|---------|
| 0xE0  | 1110 0000 | All observed data frames (SecureHeader) |

#### Observed Dctrl values

| Value | Binary     | Direction | Frame Size | Payload Size | Notes |
|-------|-----------|-----------|------------|--------------|-------|
| 0x44  | 0100 0100 | UL        | 20 bytes   | 6 bytes      | Seen once, variant frame |
| 0x54  | 0101 0100 | UL        | 19 bytes   | 5 bytes      | Standard UL data |
| 0x63  | 0110 0011 | DL        | 16 bytes   | 2 bytes      | Standard DL response |

#### Sequence Field (bytes 8-9)

The high byte (offset 8) is a monotonically increasing frame counter shared
between UL and DL directions. When parked on a single UL channel, the high
byte increments by 2 between consecutive captures (~2s apart), suggesting the
sensor transmits approximately once per 250ms across 8 channels (full cycle
~2s). The low byte (offset 9) appears to vary independently, possibly serving
as part of the encryption nonce.

### Integrity Check (4 bytes, offset 10-13)

Computed as BLAKE2b hash truncated to 4 bytes, covering:
1. First 10 bytes (cleartext header)
2. The inner header structure (packed)
3. The payload bytes (after offset 14)

This is NOT a standard CRC — it's a keyed or unkeyed BLAKE2b MAC.

### Payload (offset 14+)

For **PlainHeader** frames (beacon, discovery, connection setup):
- Payload is cleartext

For **SecureHeader** frames (data, management, key renewal):
- Payload is encrypted with `crypto_stream_xor` (XSalsa20)
- Key: session key from DH exchange
- Nonce: derived from frame header fields (24 bytes for XSalsa20)

## Frame Types

### PlainHeader Frames

#### Beacon
- Sent by gateway, broadcast on all channels
- Contains: gateway ID, channel timing, network info
- Used for device discovery and time synchronization

#### Discovery
- Sent by sensor searching for a gateway
- Contains: device MAC, capabilities
- Triggers connection flow on gateway

#### ConnectionReq
- Sensor → Gateway
- Min size: 44 bytes (`FUN_00043808` returns 0x2C)
- Max size: 76 bytes (`FUN_0004380c` returns 0x4C)
- Contains: sensor MAC, DH public key (32 bytes), capabilities

#### ConnectionRsp
- Gateway → Sensor
- Contains: gateway DH public key, challenge, ChMap

#### ChallengeReq / ChallengeRsp
- Mutual authentication using default key + DH exchange
- Contains: challenge response, confirmation

#### ChMap
- Channel assignment map
- Maps uplink channels to downlink channels

### SecureHeader Frames

#### Data
- Sensor readings (motion, entry, environmental, etc.)
- Encrypted with XSalsa20 using session key
- For important data: XSalsa20-Poly1305 (authenticated)

#### Management
- KeyRenewReq/Rsp: session key rotation
- SwitchClassA/B/C: change operating mode

## Connection Message Inner Structure

The connection handler (`FUN_000524ac`) shows that after unpacking the
PHY header, connection messages have:

```
Offset  Size  Field
------  ----  -----
0       1     Connection message type (0 = ConnectionReq, 2 = ConnectionChallenge)
...     var   Type-specific payload
```

## MAC Address Format

MAC addresses are 6 bytes, big-endian, stored at offset 2 in the
cleartext header. The unpack function (`FUN_00044bb0`) reads exactly
6 bytes from the specified offset.

## Encryption Detail

From `FUN_0003bff8` (frame decryption):

1. Copy first 10 bytes as-is (cleartext header prefix)
2. Construct a 24-byte nonce:
   - First part from header fields
   - Padded/extended to 24 bytes (XSalsa20 nonce size)
3. Allocate 0x18 (24) byte buffer for nonce construction
4. Copy 4-byte field at offset 0x14 in the nonce buffer (likely from header fields)
5. Decrypt remaining bytes with `crypto_stream_xor(plaintext, ciphertext, len, nonce, key)`

## Coding Rate

The SX1302 config template (`cfg.template.sx1302.us.json`) does not specify
an explicit coding_rate. The SX1302 HAL defaults to 4/5 when not configured.
**Confirmed via over-the-air capture**: the SX1262 sniffer successfully
receives packets with CR=4/5, so this is correct.

## Summary of LoRa PHY Parameters

| Parameter | Value | Status |
|-----------|-------|--------|
| Modulation | LoRa (CSS) | Confirmed |
| Spreading Factor | SF5 | **Confirmed OTA** |
| Bandwidth | 125 kHz (UL) / 500 kHz (DL) | **Confirmed OTA** |
| Coding Rate | 4/5 | **Confirmed OTA** |
| Sync Word | 0x1424 (private LoRa) | **Confirmed OTA** |
| Preamble | **12 symbols** (SF5/SF6 requirement) | **Confirmed OTA** |
| Header Mode | Explicit | **Confirmed OTA** |
| Payload CRC | Enabled | **Confirmed OTA** |
| Byte Order | Big-endian | Confirmed |

Note: The SX1302 HAL (Semtech sx1302_hal, loragw_sx1302.c) uses 12-symbol
preambles for SF5/SF6 and 8-symbol preambles for SF7-SF12. SF5 also has
separate syncword registers (`PEAK1_POS_SF5`, `PEAK2_POS_SF5`) from SF7-SF12.
