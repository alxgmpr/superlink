# Captured Crypto Keys and Nonce Construction

## Date: 2026-04-04

Captured via LD_PRELOAD hook on `lorabrd` intercepting libsodium calls.

**Note:** Ephemeral session keys are redacted. They are device-specific and
renegotiated on every lorabrd restart. Use the LD_PRELOAD hook (`hook4.c`) to
capture current session keys from a live gateway.

## Key Exchange Flow (on boot/reconnect)

1. **Curve25519 DH** (`crypto_scalarmult`):
   - Gateway ephemeral private key + sensor public key → shared secret
   - Shared secret: `<redacted — ephemeral, changes each session>`

2. **Connection challenge** (`crypto_secretbox_open_easy` / `crypto_secretbox_easy`):
   - Key: `<redacted — derived from DH shared secret>`
   - Nonce: `000000000000000000000000000000000000000055424e55` (ends with "UBNU")
   - Response nonce: `...55424e56` (ends with "UBNV")
   - This key is derived from DH shared secret via BLAKE2b KDF

3. **Second DH exchange** (new session):
   - New shared secret: `<redacted — ephemeral>`

## Session Keys (for ongoing data)

Two keys observed, corresponding to UL and DL directions:

| Direction | Key |
|-----------|-----|
| Key A (UL?) | `<redacted — ephemeral session key>` |
| Key B (DL?) | `<redacted — ephemeral session key>` |

Both keys used with `crypto_stream_xor` (XSalsa20 stream cipher).

## Nonce Construction (CONFIRMED — 2026-04-10)

The 24-byte XSalsa20 nonce is:

```
Byte  Source          Example (UL data frame)
----  ------          -------
0     Mctrl           0xE0
1     Dctrl           0x54 (OTA dctrl value, NOT canonical)
2-7   MAC address     90:41:B2:2E:9A:53
8     SeqHi           0x07
9     SeqLo           0x2D
10-22 Zero padding    00 00 00 00 00 00 00 00 00 00 00 00 00
23    Counter         0x02 (per-direction frame counter)
```

**Counter byte 23** is critical — NOT always zero. For UL data: counter = seq_hi - 5.
For DL data: counter = 4 (fixed, = total DL handshake frames).
See `docs/protocol/ota_captures.md` for full counter rules.

**Previous note about "canonical dctrl" was incorrect** — the nonce uses the
actual OTA dctrl value. The 0x62 value seen in earlier captures was from the
OLD session key processing an internal buffer, not the current session's nonce.

## Encryption Details

- **Data frames (0x54, 0x63)**: `crypto_stream_xor` (XSalsa20) with session key
- **Setup frames (0x44, 0x74)**: `crypto_stream_xor` (XSalsa20) with session key
- **Management frames (0x40)**: `crypto_stream_xor` (XSalsa20) with default pairing key
- **Connection frame (0x42)**: `crypto_stream_xor` with previous session key
- **Key exchange**: `crypto_secretbox` with nonce containing "UBNU"/"UBNV" ASCII markers
- **DH**: `crypto_scalarmult` (Curve25519)
- **KDF**: `crypto_generichash` (BLAKE2b) — used to derive session keys from DH shared secret

## Frame Encryption Coverage

XSalsa20 encrypts ALL bytes after the 10-byte header (MIC + payload together).
After decryption, the first 4 bytes are an integrity check and the remaining
bytes are the application payload.

```
OTA frame:  [10B header (cleartext)] [N bytes encrypted]
Decrypted:  [10B header]             [4B MIC] [payload]
```
