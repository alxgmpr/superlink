# Over-the-Air Capture Analysis

## First Capture Session — 2026-04-04

### Setup
- **Sniffer**: Heltec LoRa 32 V3 (SX1262), RadioLib
- **Gateway**: USL-Gateway (MAC 90:41:B2:34:83:DC) at 10.1.1.141
- **Sensor**: USL-Entry (MAC 90:41:B2:2E:9A:53), adopted via BLE + LoRa
- **Key fix**: Preamble changed from 8 to **12 symbols** (required for SF5)

### Radio Parameters (Confirmed)
- SF5, CR 4/5, Explicit Header, LoRa HW CRC enabled
- Sync word 0x12 (private), Preamble 12 symbols
- UL: 125 kHz, channels 915.6–917.0 MHz
- DL: 500 kHz, channels 920.4–924.6 MHz

### Sample Packets

#### Standard UL Data (sensor → gateway)
```
E0 54 90 41 B2 2E 9A 53 5B 11 9C FF C2 4C 8A 41 BC 35 D6
│  │  └──────────────┘  │  │  └─────────┘  └──────────┘
│  │   MAC: sensor       │  │   MIC (4B)    Payload (5B)
│  Dctrl=0x54 (UL data)  │  SeqLo=0x11
Mctrl=0xE0 (SecureHeader) SeqHi=0x5B
```
- **19 bytes total**: 10 header + 4 MIC + 5 encrypted payload
- RSSI: -15 to -46 dBm (sensor nearby)
- SNR: 7.2–8.5

#### Standard DL Response (gateway → sensor)
```
E0 63 90 41 B2 2E 9A 53 40 81 DB 3C 46 92 D1 AD
│  │  └──────────────┘  │  │  └─────────┘  └──┘
│  │   MAC: sensor       │  │   MIC (4B)    Pay(2B)
│  Dctrl=0x63 (DL data)  │  SeqLo=0x81
Mctrl=0xE0 (SecureHeader) SeqHi=0x40
```
- **16 bytes total**: 10 header + 4 MIC + 2 encrypted payload
- DL uses the paired channel (UL CH1→DL CH9, etc.)
- RSSI: -13 to -43 dBm

### Channel Hopping Behavior (CONFIRMED)
- **Sensor hops sequentially** through all 8 UL channels: CH1→CH2→...→CH8→CH1
- TX interval: ~2s per frame, one channel per frame
- Full cycle across 8 channels: ~16 seconds
- Gateway receives all 8 channels simultaneously (SX1302 has 8 parallel demodulators)
- Gateway responds on the paired DL channel for whichever UL channel was used
- No beacon sync observed — hopping is self-clocked round-robin
- `tbl: 2` in session setup selects the hopping table; `chs: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]` assigns all channels

**Evidence from gateway logs** (consecutive packets during session key exchange):
```
ch: 3 → ch: 4 → ch: 5   (sequential hopping during setup)
```

**Implication for sniffing**: A single-channel SX1262 sniffer (Heltec) can only capture
~1/8 of packets when parked. An SX1302/SX1303 concentrator board (e.g. RAK2287) would
receive all 8 UL channels simultaneously, matching the gateway's capability.

### Sequence Number Analysis
- **SeqHi** (byte 8): True frame counter, increments by exactly 1 per UL packet (confirmed via gateway LD_PRELOAD hook capturing complete stream)
- **SeqLo** (byte 9): Varies per frame — appears pseudo-random, likely crypto nonce component (NOT channel index)
- **DL SeqHi**: Independent frame counter, increments by 1 per DL packet
- **DL SeqLo**: Sequential (0x98, 0x99, 0x9A...) — independent DL counter
- **Nonce counter**: Last byte of the 24-byte XSalsa20 nonce increments 1:1 with packets within a session (separate from SeqHi)

### Decrypted Payload Format

**Standard UL data (5 bytes)**: `0C 00 0F 00 XX`
| Byte | Value | Meaning |
|------|-------|---------|
| 0    | 0x0C  | Type (sensor report) |
| 1    | 0x00  | Flags |
| 2    | 0x0F  | Command (door state) |
| 3    | 0x00  | Sub-command |
| 4    | 0x00/0x01 | **0x00 = OPEN, 0x01 = CLOSED** |

**Extended UL data (22 bytes)**: Sent periodically (every ~16 frames), contains sensor metadata:
```
0C 00 01 00 00 00 42 38 02 00 64 DA 07 03 00 60 0C 16 00 0F 00 00
│     │        │     │     │  │  │     │     │     │     └─ door state
│     │        │     │     │  │  │     │     │     └─ field8 (22)
│     │        │     │     │  │  │     │     └─ field7 (3168)
│     │        │     │     │  │  │     └─ field6 (3)
│     │        │     │     │  │  └─ field5 (varies: 2010, 2023, 1764) ← possible temp?
│     │        │     │     │  └─ field4=100 (0x64) ← battery %?
│     │        │     │     └─ field3 (2)
│     │        │     └─ field2 (varies: 14402, 25667, 36932) ← uptime/counter?
│     │        └─ field1 (0)
│     └─ subtype=0x01 (extended report)
└─ type=0x0C
```

**DL response (2 bytes after MIC)**: Varies per packet — purpose unknown (ACK? channel assignment? timing info?)

### Observations
1. All observed data frames use Mctrl=0xE0 (SecureHeader)
2. No beacon frames captured on CH17/927.6 MHz after 5 min observation — gateway may not broadcast beacons (Class A only?)
3. No plaintext connection frames observed (pairing already complete)
4. MIC (4 bytes) = BLAKE2b integrity check covering header + payload
5. The MAC address in DL frames is the **sensor** MAC, not the gateway MAC
6. Session keys are ephemeral — renegotiated each time lorabrd restarts (DH key exchange)

### Raw Capture Files
- `captures/capture_preamble12_20260404.log` — First successful capture (scan all)
- `captures/capture_ch1_parked_20260404.log` — Parked on UL CH1 for sequential data
