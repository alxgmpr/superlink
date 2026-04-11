# Standalone SuperLink Gateway — Design Spec

**Date:** 2026-04-11
**Status:** Draft
**Scope:** Python MVP — beacon, pairing, session establishment with factory-default sensors

## Goal

Build a standalone SuperLink gateway using the SX1302 CoreCell dev kit (RPi 4B) that can independently pair with factory-default Ubiquiti sensors and establish encrypted sessions — proving full protocol independence from Ubiquiti's gateway.

## MVP Milestone

1. Broadcast beacons on 927.6 MHz with the default pairing key
2. Accept ConnectionReq from a factory-reset sensor
3. Complete Curve25519 DH exchange and challenge authentication
4. Derive session key via BLAKE2b KDF
5. Receive and decrypt UL data frames (dctrl 0x54)
6. Log decrypted sensor data to console and CSV

Post-MVP: send DL ACK frames (dctrl 0x63) to keep the session alive.

## Architecture

### Code Location

`tools/sx1302/superlink/` — extends the existing sniffer package:

| File | Role |
|------|------|
| `hal.py` | SX1302 HAL wrapper (existing RX, add TX) |
| `decoder.py` | Frame parsing + decryption (existing, extend with encode/MIC) |
| `gateway.py` | **New.** State machine, connection manager, CLI |
| `cli.py` | Sniffer CLI (existing, unchanged) |

### State Machine

```
IDLE
  │  start()
  ▼
BEACONING ──────────────────────────────┐
  │  ConnectionReq received             │ beacon timer
  ▼                                     │
WAIT_CONNREQ                            │
  │  parse ConnectionReq, extract       │
  │  sensor MAC + Curve25519 pubkey     │
  ▼                                     │
DH_EXCHANGE                             │
  │  compute shared secret              │
  │  send ConnectionRsp (our pubkey     │
  │    + challenge + channel map)       │
  ▼                                     │
CHALLENGE                               │
  │  receive ChallengeReq               │
  │  verify (default pairing key)       │
  │  send ChallengeRsp                  │
  ▼                                     │
SESSION_KEY_DERIVATION                  │
  │  BLAKE2b KDF(shared_secret ||       │
  │    pubkey_A || pubkey_B || context)  │
  ▼                                     │
SETUP                                   │
  │  send channel map + config          │
  │  (dctrl 0x44, multiple frames)      │
  ▼                                     │
ACTIVE                                  │
  │  decrypt UL data (0x54), log it     │
  │  (post-MVP: send DL ACK 0x63)      │
  │                                     │
  │  timeout / error ──────────────────►│
  └─────────────────────────────────────┘
```

Each state is a method on a `GatewaySession` class. The main loop polls `hal.receive()` and dispatches to the current state handler.

### Crypto Layer

Extend `decoder.py` with encoding/encryption functions:

```python
# New functions
def build_nonce(mctrl, dctrl, mac, seq_hi, seq_lo, counter) -> bytes  # exists, reuse
def encrypt_payload(payload, mic, key, nonce) -> bytes
def compute_mic(header_10b, payload) -> bytes  # 4-byte BLAKE2b
def build_frame(mctrl, dctrl, mac, seq_hi, seq_lo, payload, key, counter) -> bytes

# New in gateway.py (session-level crypto)
def generate_keypair() -> (privkey, pubkey)  # Curve25519
def compute_shared_secret(privkey, remote_pubkey) -> bytes
def derive_session_key(shared_secret, pubkey_a, pubkey_b, context) -> bytes
# context bytes TBD — must be determined from keyhook capture of real KDF call
```

All crypto via `pysodium` (libsodium Python bindings), already in the venv.

### Radio Layer (HAL Extension)

Add to `hal.py`:

```python
def send(self, freq_hz, payload, tx_mode=TX_IMMEDIATE):
    """Transmit a frame via SX1302."""
    # ctypes wrapper around lgw_send()
    # Params: freq, SF5, BW 500kHz (DL), CR 4/5, sync 0x1424,
    #         preamble 12, explicit header, CRC on
```

TX parameters for DL:
- Frequency: paired DL channel (920.4–924.6 MHz) or 927.6 MHz (beacon)
- Bandwidth: 500 kHz
- SF: 5
- Coding rate: 4/5
- Sync word: 0x1424
- Preamble: 12 symbols

### Frame Formats

**Beacon (plaintext, Mctrl=0x00):**
```
[Mctrl 1B][Dctrl 1B][GW_MAC 6B][SeqHi 1B][SeqLo 1B][Beacon payload ?B]
```
Beacon payload fields TBD — need to capture a real beacon to confirm. Likely includes firmware version, capabilities, channel map.

**ConnectionRsp (plaintext):**
```
[Mctrl 1B][Dctrl 1B][GW_MAC 6B][SeqHi 1B][SeqLo 1B]
[GW Curve25519 pubkey 32B][Challenge ?B][ChMap ?B]
```
Exact field layout TBD — need to capture a real ConnectionRsp to map byte offsets.

**ChallengeRsp (encrypted with default pairing key):**
```
[Header 10B][Encrypted(MIC 4B + challenge_response ?B)]
```

**DL Data ACK (encrypted with session key, dctrl=0x63):**
```
[Header 10B][Encrypted(MIC 4B + ACK payload 2B)]
```
ACK format observed in captures: 16B total (10B header + 6B encrypted → 4B MIC + 2B payload).

### Unknowns Requiring Capture Verification

These fields are identified in binary analysis but not yet confirmed OTA:

1. **Beacon payload structure** — What fields does the sensor expect? Priority: HIGH. Cannot start without this.
2. **ConnectionReq/Rsp byte layout** — Field offsets within the 44-76B payload. Priority: HIGH.
3. **Challenge computation** — Exact hash/encrypt operation for challenge-response. Priority: HIGH.
4. **KDF additional_data / extra_context** — What goes into the BLAKE2b beyond shared_secret + pubkeys. Priority: HIGH.
5. **DL TX timing** — How soon after UL RX must the DL response arrive? Priority: MEDIUM (post-MVP).
6. **Beacon interval** — Confirmed ~240s from observation, but sensor tolerance unknown. Priority: LOW.

### Mitigation: Capture-First Development

For each handshake stage:
1. Use keyhook + sniffer to capture the real gateway's frame
2. Decode the captured frame byte-by-byte
3. Implement our version to produce identical output
4. Unit test against the captured frame as ground truth

This means the capture task (Task 1) directly feeds gateway development.

## Testing Strategy

### Unit Tests (`tests/test_gateway.py`)

**Crypto tests:**
- XSalsa20 encrypt/decrypt round-trip with known key/nonce
- Known-answer test: encrypt a captured plaintext with captured key/nonce, compare to captured ciphertext
- BLAKE2b KDF: compute session key from captured DH inputs, compare to captured session key
- MIC computation: compute MIC over captured frame, compare to captured MIC
- Nonce construction: verify nonce bytes for each dctrl/counter combination

**Frame tests:**
- `build_frame()` → `parse_frame()` round-trip recovers all fields
- `build_frame()` output matches a captured frame byte-for-byte
- Frame with known key encrypts/decrypts correctly

**State machine tests:**
- Feed synthetic events, assert correct state transitions
- Verify correct frame type produced at each stage
- Timeout handling: verify return to BEACONING on connection loss
- Reject malformed ConnectionReq (wrong size, bad MAC)

**Test data directory:** `tests/fixtures/`
- Captured frames (raw hex) from keyhook + sniffer sessions
- Corresponding keys, nonces, plaintexts
- Used as protocol ground truth

### Integration Tests (Manual, Hardware Required)

- HAL TX test: transmit a frame, verify on spectrum analyzer or second radio
- Full handshake against a factory-reset sensor
- Session persistence: verify sensor continues sending data after handshake

## CLI Interface

```
superlink-gw --mac AA:BB:CC:DD:EE:FF [--beacon-interval 240] [--log capture.csv] [--verbose]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--mac` | Gateway MAC to advertise (required) | — |
| `--beacon-interval` | Seconds between beacon TX | 240 |
| `--log` | CSV log file for all RX/TX frames | — |
| `--verbose` | Print raw hex + crypto details | off |

Output format matches the sniffer for consistency:
```
14:23:01 BEACON TX 927.6 MHz  [our beacon]
14:25:33 CONNREQ RX CH3  90:41:B2:2E:9A:53  44B
14:25:33 CONNRSP TX CH11 90:41:B2:2E:9A:53  48B
...
14:25:38 DATA RX CH5  seq=06.35  19B  DOOR CLOSED
```

## Dependencies

- `pysodium` — libsodium bindings (Curve25519, XSalsa20, BLAKE2b)
- `libloragw` — SX1302 HAL (already built on RPi)
- Python 3.11+ (RPi OS default)
- Existing: `hal.py`, `decoder.py` from sniffer package

## Out of Scope (for this MVP)

- Multiple simultaneous sensor sessions
- Key renewal / re-keying
- Management frames (dctrl 0x40)
- UniFi controller integration
- C port
- Production reliability (watchdog, error recovery)
