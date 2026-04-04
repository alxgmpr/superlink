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

### Channel Hopping Behavior
- Sensor hops across all 8 UL channels
- Approximate TX interval: ~250ms per hop, ~2s full cycle
- Gateway responds on paired DL channel
- Hopping pattern appears pseudo-random or sequential (needs more data)

### Sequence Number Analysis
- SeqHi (byte 8): Frame counter, shared UL+DL, monotonically increasing
- SeqLo (byte 9): Varies per frame, likely crypto nonce component
- When parked on CH1: SeqHi increments by 2 between consecutive captures

### Observations
1. All observed data frames use Mctrl=0xE0 (SecureHeader)
2. No beacon frames captured yet (may need longer observation on CH17/927.6 MHz)
3. No plaintext connection frames observed (pairing already complete)
4. Payload is encrypted — 5 bytes UL, 2 bytes DL for standard data
5. MIC (4 bytes) = BLAKE2b integrity check covering header + payload
6. The MAC address in DL frames is the **sensor** MAC, not the gateway MAC

### Raw Capture Files
- `captures/capture_preamble12_20260404.log` — First successful capture (scan all)
- `captures/capture_ch1_parked_20260404.log` — Parked on UL CH1 for sequential data
