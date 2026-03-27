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
8       2     ???       uint16_t             Possibly frame counter or session ID
```

The Mctrl and Dctrl bytes are bitfield structures (classes `phypayload::Mctrl`
and `phypayload::Dctrl`). Their exact bit layout needs further RE, but they
likely encode:
- Frame type (beacon, discovery, connection, data, management)
- Direction (uplink vs downlink)
- Encryption flag (plain vs secure)
- Ack request flag
- Sequence number bits

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

Not yet confirmed from decompilation. The SX1302 config path supports
"4/5", "4/6", "4/7", "4/8" (from error string at sx1302_config.c-812).
Default for most LoRa is 4/5. The JSON config template doesn't specify
an explicit coding_rate, suggesting the default (4/5) is used.

## Summary of LoRa PHY Parameters

| Parameter | Value |
|-----------|-------|
| Modulation | LoRa (CSS) |
| Spreading Factor | SF5 |
| Bandwidth | 125 kHz (UL) / 500 kHz (DL) |
| Coding Rate | 4/5 (default, unconfirmed) |
| Sync Word | 0x1424 (private LoRa) |
| Preamble | 8 symbols (default, unconfirmed) |
| Header Mode | Explicit (standard LoRa) |
| Payload CRC | Likely enabled |
| Byte Order | Big-endian |
