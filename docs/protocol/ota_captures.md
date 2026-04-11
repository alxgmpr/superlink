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

## Second Capture Session — 2026-04-10

### Setup
- **Sniffer**: SX1302 CoreCell (SX1250 radios) + RPi 4B, all 8 UL channels simultaneously
- **Gateway**: USL-Gateway (same as above)
- **Sensor**: USL-Entry (same as above)
- **Software**: Custom Python sniffer (`tools/sx1302/`) with ctypes HAL wrapper

### Steady-State Packet Sizes

| Size | Payload | Dctrl | Frequency | Description |
|------|---------|-------|-----------|-------------|
| 19B  | 5B      | 0x54  | Every ~2s | Standard UL data (door state) |
| 22B  | 8B      | 0x54/0x40 | Periodic | Mid-size report (new dctrl 0x40 observed) |
| 36B  | 22B     | 0x54  | Every ~16 frames | Extended report (battery, temp, uptime) |

### Reconnection Handshake (captured OTA after lorabrd restart)

When the sensor reconnects after losing the gateway, the following frame sequence occurs:

```
Time     Size  Dctrl  Seq      Description
19:55:07  63B  0x42   DE.34    Connection/challenge frame (49B payload)
19:55:08  16B  0x53   01.2C    Response frame (2B payload)
19:55:09  92B  0x44   02.81    Large setup frame (78B payload)
19:55:10  41B  0x44   03.82    Setup continued (27B payload)
19:55:11  20B  0x44   04.83    Setup continued (6B payload)
19:55:12  41B  0x44   05.84    Setup continued (27B payload)
19:55:16  36B  0x54   06.35    First data frame (extended report)
```

The same sequence repeated at 20:00 (second reconnection attempt), confirming it's deterministic.

#### New Dctrl Values Observed

| Value | Direction | Context | Notes |
|-------|-----------|---------|-------|
| 0x42  | UL | Reconnection | Connection/challenge, 63B frame, 49B payload contains DH pubkey? |
| 0x53  | DL? | Reconnection | Response, 16B frame, matches DL data size |
| 0x44  | UL | Reconnection | Multi-frame setup (92B, 41B, 20B sizes), seq_lo increments 0x81→0x84 |
| 0x40  | UL | Steady-state | Seen on 22B frame, new variant of data-ext |

#### Reconnection Timing
- Sensor backoff after losing gateway: **~5 minutes** before first reconnection attempt
- Second attempt follows ~5 minutes after first
- During backoff, sensor transmits nothing on UL channels

### Session Key Capture (LD_PRELOAD hook)

Successfully captured session keys by hooking `crypto_stream_xor` in `lorabrd`:
- **Tool**: `tools/keyhook/keyhook.c` — cross-compiled for armv7l (gateway arch)
- **Method**: LD_PRELOAD on lorabrd, logs unique keys to `/tmp/keyhook.log`
- **Result**: Session key + default pairing key captured, with per-packet nonces
- **Caveat**: Keys rotate on every lorabrd restart; sensor takes ~5 min to reconnect

### Nonce Construction (CONFIRMED via keyhook)

The 24-byte XSalsa20 nonce is constructed as follows:

```
Byte   Source          Example (UL data)
----   ------          ---------
0      Mctrl           0xE0
1      Dctrl           0x54 (OTA value, NOT canonical)
2-7    MAC address     90:41:B2:2E:9A:53
8      SeqHi           0x07
9      SeqLo           0x2D
10-22  Zero padding    00 00 00 00 00 00 00 00 00 00 00 00 00
23     Counter         0x02 (UL frame counter)
```

**Counter rules** (derived from keyhook per-packet nonce analysis):
- **UL data (0x54)**: counter = seq_hi - 5 (= number of UL data frames since session start)
- **UL setup (0x44)**: counter = 1 (fixed during handshake)
- **DL data (0x63)**: counter = 4 (= total DL handshake frames, fixed after handshake)
- **DL handshake (0x74)**: counter increments 0, 1, 2, 3...
- The "5" offset = number of UL handshake frames (seq_hi 01-05) in a reconnection

**The counter in nonce byte 23 was the missing piece** — previous attempts used all-zero trailing bytes, which only works for the very first frame.

### Confirmed Decryption (36B extended report)

Successfully decrypted a 36B UL data frame captured OTA:
```
Frame: E0 54 9041B22E9A53 0D 2D [26B encrypted]
Key:   3bfc41760a9eb10c01989bfdbfc384f770617d7a5bfa56acc72d90edeefb8c06
Nonce: E0 54 9041B22E9A53 0D 2D 00...00 08  (counter = 0x0D - 5 = 8)

Decrypted: [MIC 4B] 0C 00 01 00 00 08 6E 04 02 00 64 E0 07 03 00 60 0C 16 00 0F 00 00
                     ^type  ^sub     ^uptime? ^?  ^bat ^temp ^?  ^?     ^?  ^door=OPEN
```

Payload matches the extended report format from the first session exactly.

### Keys Per Session

A reconnection session uses these keys (from keyhook analysis):
1. **Old session key** — used to decrypt the incoming 0x42 connection frame (from sensor, encrypted with previous session key)
2. **New session key** — derived via DH exchange, used for all subsequent frames:
   - 0x44 setup frames (UL, counter=1)
   - 0x54 data frames (UL, counter=seq_hi-5)
   - 0x53/0x74 handshake responses (DL)
   - 0x63 data responses (DL, counter=4)
3. **Default pairing key** — used for 0x40 management/keepalive frames (independent seq counter)

### Key Finding: Dctrl Byte Encodes Frame Type + Direction

| Dctrl | Direction | Frame Type | Crypto Key | Counter | Size Range |
|-------|-----------|------------|------------|---------|------------|
| 0x40  | UL | Management/keepalive | Default pairing key | 0? | 22B |
| 0x42  | UL | Connection/Challenge | Old session key | 0 | 63B |
| 0x43  | DL | Management ack | Session key? | ? | 16B |
| 0x44  | UL | Setup/Config data | Session key | 1 | 20-92B |
| 0x53  | DL | Connection response | Session key | 0 | 16B |
| 0x54  | UL | Standard data | Session key | seq_hi-5 | 19-36B |
| 0x63  | DL | Standard data | Session key | 4 | 16B |
| 0x74  | DL | Setup response | Session key | 0-3 | 16B |

### Raw Capture Files
- `captures/capture_preamble12_20260404.log` — First successful capture (scan all)
- `captures/capture_ch1_parked_20260404.log` — Parked on UL CH1 for sequential data
