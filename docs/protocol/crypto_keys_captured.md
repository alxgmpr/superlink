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

## Nonce Construction (CONFIRMED)

The 24-byte XSalsa20 nonce is constructed from the packet header:

```
Byte  Source          Example
----  ------          -------
0     Mctrl           0xE0
1     Dctrl           0x62 (UL) or 0x44 (DL) etc
2-7   MAC address     90:41:B2:2E:9A:53
8-9   Seq (hi, lo)    0x40, 0x11
10-19 Zero padding    00 00 00 00 00 00 00 00 00 00
20-23 Counter?        00 00 00 00 (increments for multi-block)
```

Confirmed by matching hook output nonces to captured packet headers:
- `e062<MAC><SEQ>0000000000000000000000000000` matches mctrl=0xE0, dctrl=0x62, MAC=device MAC, seq=frame counter

## Encryption Details

- **Data frames**: `crypto_stream_xor` (XSalsa20, no authentication at frame level)
- **Management frames**: `crypto_secretbox` (XSalsa20-Poly1305, authenticated)
- **Key exchange**: `crypto_secretbox` with nonce containing "UBNU"/"UBNV" ASCII markers
- **DH**: `crypto_scalarmult` (Curve25519)
- **KDF**: `crypto_generichash` (BLAKE2b) — used to derive session keys from DH shared secret

## Captured Nonce-to-Packet Mapping

```
stream_xor len=45 nonce=e062<MAC><SEQ>0000... → UL packet mctrl=E0 dctrl=62
stream_xor len=53 nonce=e042<MAC><SEQ>0000... → UL packet mctrl=E0 dctrl=42
stream_xor len=22 nonce=e062<MAC><SEQ>0000... → UL packet mctrl=E0 dctrl=62
stream_xor len=9  nonce=e054<MAC><SEQ>0000... → DL packet mctrl=E0 dctrl=54
```

Note: The dctrl in the nonce may differ from what we see OTA — the nonce uses the
"canonical" dctrl before direction-specific modifications.
