# SuperLink Protocol Structure (from lorabrd binary analysis)

## Source
Binary: `lorabrd` (ubnt-lora-bridge) from UP-Sense-Link firmware v1.9.0
Build path: `/home/uldis/ui/protect/uvc-psl/openwrt-genls-rel/build_dir/target-arm-openwrt-linux-gnu_glibc/ubnt-lora-bridge/`

## Source Files (from debug strings)
```
src/rail_drivers/sx1302/sx1302_caps.c
src/rail_drivers/sx1302/sx1302_config.c
src/rail_drivers/sx1302/sx1302_lgw.c
src/rail_drivers/sx1302/sx1302_rx.c
src/rail_drivers/sx1302/sx1302_scan.c
src/rail_drivers/sx1302/sx1302_thread.c
src/rail_drivers/sx1302/sx1302_time.c
src/rail_drivers/sx1302/sx1302_tx.c
```

## Packet Hierarchy (from C++ RTTI symbols)

### Physical Layer Payload (`ubnt::lorapack::phypayload`)
```
phypayload::Header       — Common PHY header
phypayload::PlainHeader  — Unencrypted header variant
phypayload::SecureHeader — Encrypted header variant
phypayload::Dctrl        — Data control field
phypayload::Mctrl        — Management control field
```

### Connection Layer (`ubnt::lorapack::connection`)
```
connection::Header              — Connection header
connection::ConnectionReq       — Connection request (device → gateway)
connection::ConnectionRsp       — Connection response (gateway → device)
connection::ConnectionChallenge — Authentication challenge
connection::ChallengeReq        — Challenge request
connection::ChallengeRsp        — Challenge response
connection::ChMap               — Channel map (tells device which channels to use)
```

### Management Layer (`ubnt::lorapack::management`)
```
management::Header         — Management header
management::KeyRenewReq    — Key renewal request
management::KeyRenewRsp    — Key renewal response
management::SwitchClassAReq — Switch to Class A (uplink-initiated, like LoRaWAN Class A)
management::SwitchClassARsp
management::SwitchClassBReq — Switch to Class B (beacon-synchronized)
management::SwitchClassBRsp
management::SwitchClassCReq — Switch to Class C (continuous receive)
management::SwitchClassCRsp
```

### Other Packet Types
```
lorapack::Beacon    — Beacon frame (gateway broadcasts)
lorapack::Discovery — Discovery frame (device searching for gateway)
```

## Protocol Classes (from symbols)

### Core Classes
```
LoRaIface              — Radio interface manager
LoRaDevice             — Connected device representation
LoRaBeacon / LoRaBeacons — Beacon management
LoRaDlScheduler        — Downlink scheduler (TDMA-like time slots)
LoRaDlTimeSlotCtx      — Downlink time slot context
LoRaDlSocket           — Downlink socket abstraction
LoRaDlMsgCtx           — Downlink message context
LoRaExchangeCtx        — Data exchange context
LoRaTransmission       — Transmission object
LoRaIfaceUser          — User-facing interface (discovery, etc.)
```

### API Classes
```
ApiUcp4If              — API interface using UCP4 protocol (WebSocket-based)
  → HandshakeState     — TLS/DH handshake state
  → WaitingState       — Waiting for connection
  → ActiveState        — Active session
  → ShutdownState      — Shutting down
ApiUcp4WsServer        — WebSocket server for management
DhSession              — Diffie-Hellman key exchange session
```

### Device API Classes
```
LoRaIfaceProApi         — Interface professional API
LoRaIfaceProUserApi     — User management API
LoRaIfaceProRadioApi    — Radio configuration API
LoRaIfaceProDeviceApi   — Device management API
LoRaDeviceProApi        — Device professional API
```

### Radio Driver Classes
```
rail_drivers::Device           — Generic radio device
rail_drivers::DeviceAdapterC   — C adapter for the radio driver
rail_drivers::tunnel::Device   — Tunnel device (TCP bridge)
rail_drivers::tunnel::Config   — Tunnel configuration
rail_drivers::tunnel::TcpConnection — TCP connection for tunnel
rail_drivers::tunnel::pack::*  — Tunnel packet types:
  → Capabilities, Channel, Schedules, Period
  → TxMsg, RxMsg, TxDurationReq, TxDurationResp
  → SpectralScanResult, SpectralScanResults
  → State, Error
```

## Crypto
- **DhSession** — Diffie-Hellman key exchange (for session establishment)
- **PKCS5_PBKDF2_HMAC** with SHA1/SHA256/SHA512 variants (key derivation)
- **XOR crypto stream** (lightweight encryption?)
- AES implied by "Invalid size of key" / "Invalid size of nonce" errors
- Session keys confirmed, with key renewal mechanism

## Connection Flow (inferred)
1. Gateway broadcasts **Beacon** frames on configured channels
2. Device sends **Discovery** frame
3. Device sends **ConnectionReq**
4. Gateway responds with **ConnectionRsp**
5. **ConnectionChallenge** / **ChallengeReq** / **ChallengeRsp** — mutual authentication
6. **DhSession** — Diffie-Hellman key exchange establishes session key
7. Gateway sends **ChMap** — assigns channels to device
8. Device enters active state (Class A/B/C)
9. **KeyRenewReq/Rsp** — periodic key rotation

## Channel Plan (US, from config)

### Uplink Channels (125 kHz, SF5)
| CH | Freq (MHz) | IF Chain | Dwell (ms) | Period (ms) |
|----|-----------|----------|------------|-------------|
| 1  | 915.6     | 0        | 400        | 20000       |
| 2  | 915.8     | 1        | 400        | 20000       |
| 3  | 916.0     | 2        | 400        | 20000       |
| 4  | 916.2     | 3        | 400        | 20000       |
| 5  | 916.4     | 4        | 400        | 20000       |
| 6  | 916.6     | 5        | 400        | 20000       |
| 7  | 916.8     | 6        | 400        | 20000       |
| 8  | 917.0     | 7        | 400        | 20000       |

### Downlink Channels (500 kHz, SF5)
| CH  | Freq (MHz) | Dwell (ms) | Period (ms) |
|-----|-----------|------------|-------------|
| 9   | 920.4     | 400        | 10000       |
| 10  | 921.0     | 400        | 10000       |
| 11  | 921.6     | 400        | 10000       |
| 12  | 922.2     | 400        | 10000       |
| 13  | 922.8     | 400        | 10000       |
| 14  | 923.4     | 400        | 10000       |
| 15  | 924.0     | 400        | 10000       |
| 16  | 924.6     | 400        | 10000       |

### Special Channel
| CH  | Freq (MHz) | BW     | Note |
|-----|-----------|--------|------|
| 17  | 927.6     | 500kHz | Beacon? Standalone DL? |

### Channel Pairs (Uplink → Downlink)
```
CH1 (915.6) → CH9  (920.4)
CH2 (915.8) → CH10 (921.0)
CH3 (916.0) → CH11 (921.6)
CH4 (916.2) → CH12 (922.2)
CH5 (916.4) → CH13 (922.8)
CH6 (916.6) → CH14 (923.4)
CH7 (916.8) → CH15 (924.0)
CH8 (917.0) → CH16 (924.6)
```

## Key Parameters
- **Spreading Factor: SF5** (very fast, short range — unusual, not standard LoRaWAN)
- **lorawan_public: false** (custom sync word, not LoRaWAN)
- **Beacon delay: 240,000,000 μs = 240 seconds**
- **DL retry delay: 4,000,000 μs = 4 seconds**
- **Uplink dwell period: 20 seconds per channel**
- **Downlink dwell period: 10 seconds per channel**
- **Dwell time: 400 ms** (FCC maximum)
- Supports Class A, B, and C operation modes (like LoRaWAN but proprietary)
