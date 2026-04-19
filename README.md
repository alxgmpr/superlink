# OpenSuperLink

Reverse engineering of Ubiquiti's proprietary SuperLink protocol — a LoRa-based sub-GHz radio system on 915 MHz (US ISM band). Listening to packets using a Heltec v3.

<img width="1028" height="781" alt="image" src="https://github.com/user-attachments/assets/e16ffbb9-7369-461f-b2e1-0df24a7cf506" />

## What is SuperLink?

SuperLink is Ubiquiti's proprietary long-range wireless protocol used in UniFi Access, UniFi Connect, UniFi SmartPower, and gateway products. It uses standard Semtech LoRa chirp spread spectrum modulation but a completely proprietary MAC layer with custom framing, encryption, and device management. It is not LoRaWAN.


## Hardware

- Hub side: Semtech SX1302 digital baseband (8 simultaneous RX channels)
- Peripheral side: Semtech SX1262 single-channel LoRa transceiver (+22 dBm)
- RF front-end: Skyworks SKY66420-11 (860–930 MHz PA/LNA)

## LoRa PHY Parameters

All confirmed over-the-air:

| Parameter | Value |
|-----------|-------|
| Spreading Factor | SF5 |
| Bandwidth (UL) | 125 kHz |
| Bandwidth (DL) | 500 kHz |
| Coding Rate | 4/5 |
| Sync Word | 0x1424 (private LoRa) |
| Preamble | 12 symbols (SF5/SF6 requirement) |
| Header Mode | Explicit |
| Byte Order | Big-endian |

8 UL channels: 915.6–917.0 MHz (125 kHz, SF5)
8 DL channels: 920.4–924.6 MHz (500 kHz, SF5)
Beacon channel: 927.6 MHz

## Frame Format

```
Offset  Size  Field
------  ----  -----
0       10    Cleartext header (always unencrypted)
10      4     Integrity check (BLAKE2b truncated to 4 bytes)
14      N     Payload (XSalsa20-encrypted for SecureHeader frames)
```

Cleartext header (10 bytes):
```
Offset  Size  Field
------  ----  -----
0       1     Mctrl (management/message control)
1       1     Dctrl (data control)
2       6     MAC address (source or destination)
8       1     SeqHi (frame counter, increments per packet)
9       1     SeqLo (nonce component, pseudo-random)
```

Observed frame types by Dctrl:
- 0x54: standard UL data (19 bytes total: 10 header + 4 MIC + 5 payload)
- 0x44: variant UL data (20 bytes total: 10 header + 4 MIC + 6 payload)
- 0x63: standard DL response (16 bytes total: 10 header + 4 MIC + 2 payload)

All observed data frames use Mctrl=0xE0 (SecureHeader).

## Decrypted Payload (USL-Entry door sensor)

Standard 5-byte UL payload:
```
Byte 0: 0x0C  type (sensor report)
Byte 1: 0x00  flags
Byte 2: 0x0F  command (door state)
Byte 3: 0x00  sub-command
Byte 4: 0x00/0x01  door state (0x00=open, 0x01=closed)
```

Extended 22-byte UL payload (sent periodically every ~16 frames):
contains sensor metadata including what appears to be battery level (0x64 = 100%),
uptime counter, and possibly temperature readings.

## Crypto

- Session keys: Curve25519 ECDH, renegotiated each time lorabrd restarts
- Data encryption: XSalsa20 (stream cipher via crypto_stream_xor)
- Authenticated encryption: XSalsa20-Poly1305 for important frames
- Integrity: BLAKE2b (4-byte truncated MAC, covers header + payload)
- Nonce: 24 bytes, derived from frame header fields; last byte increments per packet
- Pairing: hardcoded default key used during initial device adoption (see docs/protocol/crypto_and_pairing.md)

## Channel Hopping

The sensor hops sequentially through all 8 UL channels (CH1→CH2→...→CH8→repeat).
One frame per channel, ~2s TX interval, full 8-channel cycle takes ~16 seconds.
The gateway listens on all 8 UL channels simultaneously and responds on the paired DL channel.
A single-channel SX1262 sniffer captures roughly 1/8 of packets when parked on one channel.

## Gateway Emulator

A standalone Python gateway running on a Raspberry Pi + SX1302 concentrator
board. It implements the SuperLink MAC well enough to pair with a
factory-default sensor over the air — Curve25519 DH exchange, BLAKE2b session
key derivation, XSalsa20-Poly1305 authenticated DL frames, and a connection
state machine (beacon → ConnReq → DH → challenge → active). Lives in
`tools/sx1302/superlink/` as a Python package with modules for the HAL,
decoder/encoder, crypto, and the gateway state machine, plus TX and delay
sweep harnesses for tuning DL responses.

## Repository Structure

```
superlink/
├── docs/protocol/          — frame format, crypto, channel plan, OTA captures
├── docs/teardowns/         — hardware component identification
├── tools/sniffer/          — PlatformIO project: Heltec V3 + SX1262 packet sniffer
├── tools/sx1302/           — SX1302-based Pi gateway: sniffer, emulator, sweeps
│   └── superlink/          — Python package (hal, decoder, crypto, gateway, cli)
├── tools/emulator/         — sensor-side emulator scaffolding
├── tools/keyhook/          — runtime key capture helper for lorabrd
├── tools/decoder/          — placeholder for Wireshark dissector
├── tools/sdr/              — GNU Radio capture notes
├── firmware/dumps/         — extracted firmware images (gitignored)
├── src/                    — reserved for protocol library (currently empty)
└── research/               — research tracking
```

See [docs/RE_PLAN.md](docs/RE_PLAN.md) for the phased reverse engineering roadmap.

## Legal

Interoperability research under applicable reverse engineering exemptions. Based on publicly available FCC filings, over-the-air captures (legal under FCC Part 15), and firmware analysis for interoperability purposes.

## License

MIT
