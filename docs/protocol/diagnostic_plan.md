# SuperLink Pairing Diagnostic Plan

## Problem Statement

We can receive the sensor's 0x40 discovery frames, build and transmit a 0x62 ConnectionRsp, but the sensor never responds with a 0x42 ConnectionChallenge. After exhaustive testing of 12 timing/IQ combinations (0ms-4s delays, normal and inverted IQ), zero responses were observed. From firmware RE we confirmed `invert_pol=false` and that the real gateway responds to 0x40 directly (no beacon required). **We don't know whether our TX frames actually reach the air.**

## Available Hardware

| Device | Chip | Role | Location |
|--------|------|------|----------|
| SX1302 CoreCell #1 + RPi 4B | SX1302+SX1250 | Gateway / TX | 10.1.1.87, `~/.ssh/id_ed25519_pi` |
| SX1302 CoreCell #2 + RPi | SX1302+SX1250 | DL monitor / verifier | New — needs IP/setup |
| Heltec LoRa 32 V3 | SX1262 | Single-channel sniffer | USB serial, PlatformIO |
| USL-Entry sensor | SX1262 | Target device | Factory reset, battery powered |
| USL-Gateway (Ubiquiti) | SX1302+SX1250 | Reference gateway | 10.1.1.141, SSH via `ubnt`/webpass |

## Phase 1: Verify TX Actually Works (RF-level)

**Goal**: Determine if `lgw_send` on Board 1 actually produces RF output on the correct DL frequency.

### Setup
```
Board 1 (10.1.1.87):  UL-only mode, runs gateway
                       Receives 0x40 on UL, transmits 0x62 on DL

Board 2 (new):         Combined UL+DL mode, runs capture.py
                       Radio A: all 8 UL channels (125 kHz)
                       Radio B + IF8: one DL channel (500 kHz)
                       Passively listens — captures our own TX

Sensor:                Battery in, sending 0x40 discoveries
```

### Procedure
1. Note which UL channel the sensor is using (it hops, but `ch=N` is logged)
2. Configure Board 2's `--dl-channel` to the paired DL: `UL CH N` → `DL CH (N+8)`
3. Start Board 2: `python -m superlink.capture --dl-channel <N+8>`
4. Start Board 1: gateway with `--tx-delay 0` (immediate TX)
5. Wait for a discovery + TX cycle
6. **Check Board 2 logs**: did it receive a DL frame?

### Interpreting Results
- **Board 2 receives our 0x62**: TX works. Problem is frame content or sensor RX window.
- **Board 2 receives nothing on DL**: TX is broken. Investigate HAL TX path, antenna, rf_chain config.
- **Board 2 receives garbled DL**: TX works but wrong parameters (BW, SF, sync word).

### Fallback: Use Heltec as DL Verifier
If Board 2 isn't available yet, park the Heltec on the expected DL frequency:
```
Frequency: DL_FREQ_HZ[ul_channel - 1]  (e.g., 922.2 MHz for UL CH4)
BW: 500 kHz, SF5, sync word 0x12 (private), preamble 12
```
Modify `tools/sniffer/src/main.cpp` to park on a DL freq with 500 kHz BW. Any received packet confirms TX is on the air.

## Phase 2: Capture Real Gateway's 0x62 (Reference Capture)

**Goal**: Capture the actual bytes the Ubiquiti gateway sends in response to a sensor discovery. We have **never captured a real 0x62** — our format was inferred from firmware analysis.

### Setup
```
Ubiquiti GW (10.1.1.141):  Powered on, discovery mode enabled
                            (trigger via UniFi Protect UI: adopt new sensor)

Board 1 (10.1.1.87):       Combined UL+DL mode, capture.py
                            --dl-channel <paired with sensor's UL>

Board 2 (new):              Combined UL+DL mode, capture.py
                            --dl-channel <different DL> (cover more channels)

Heltec:                     Parked on beacon channel 927.6 MHz, 500 kHz BW
                            (check if gateway sends beacons during pairing)

Sensor:                     Factory reset, battery in
```

### Procedure
1. Power on Ubiquiti gateway, enable adoption in UniFi Protect
2. Start both boards on different DL channels (e.g., CH10 and CH12)
3. Start Heltec on 927.6 MHz
4. Insert sensor battery
5. Watch for:
   - UL 0x40 discoveries (both boards will see these)
   - **DL 0x62 from real gateway** (one board should catch it on the right DL channel)
   - Beacon frames on 927.6 MHz (Heltec)
   - UL 0x42 ConnectionChallenge (confirms pairing is progressing)
6. If the 0x62 lands on a DL channel neither board is monitoring, note which UL channel the sensor used and restart with the correct `--dl-channel`

### What to Capture
- **Full raw hex** of the gateway's 0x62 frame
- **Decrypted payload** (pairing key is known)
- **Timing**: delay between sensor's 0x40 TX and gateway's 0x62 TX
  - Board 1 sees both UL and DL with SX1302 timestamps — compute `dl_timestamp - ul_timestamp`
- **Beacon presence**: does the gateway beacon on 927.6 MHz before/during pairing?

### Key Questions This Answers
1. What is the exact 0x62 wire format? (Compare with our constructed frame)
2. What DL channel does the gateway use? (Verify our UL→DL pairing)
3. What is the TX delay? (Immediate? Scheduled? How many ms after RX?)
4. Does the gateway send beacons during pairing?
5. What are the first 2 payload bytes (inner type) and the 7-byte header?

## Phase 3: Diff and Fix

**Goal**: Compare captured real 0x62 with our constructed one, fix differences, achieve pairing.

### Compare Points
| Field | Our value | Real gateway | Notes |
|-------|-----------|-------------|-------|
| Mctrl | 0xE0 | ? | SecureHeader |
| Dctrl | 0x62 | ? | Might be different! |
| MAC | sensor MAC | ? | Confirmed from docs |
| SeqHi/Lo | incrementing | ? | |
| MIC | BLAKE2b | ? | Verified algorithm |
| Payload[0:2] | 0x01, 0x01 | ? | outer type, inner type |
| Payload[2:9] | 74ad9482f05344 | ? | 7B inner header (stale?) |
| Payload[9:41] | our pubkey | ? | 32B Curve25519 |
| Total size | 55B (10+4+41) | ? | |

### Common Failure Modes
- **Wrong dctrl**: Maybe initial pairing uses a different dctrl than 0x62
- **Wrong inner header**: The 7 bytes `74ad9482f05344` may be session-specific
- **Wrong payload structure**: Real gateway may use different offsets/lengths
- **Encryption error**: Counter or nonce construction might differ for DL 0x62
- **Missing beacon**: Gateway may need to beacon first to enable sensor RX

## Phase 4: Full Independent Pairing

Once we can replicate the exact 0x62 format, run the complete handshake:

```
Sensor → Board 1:   0x40 Discovery (UL, pairing key)
Board 1 → Sensor:   0x62 ConnectionRsp (DL, pairing key, our pubkey)
Sensor → Board 1:   0x42 ConnectionChallenge (UL, pairing key, sensor pubkey)
Board 1 → Sensor:   0x62 ChallengeRsp (DL, pairing key)
Sensor → Board 1:   0x44 Setup frames (UL, session key)
Board 1 → Sensor:   0x74 Setup response (DL, session key)
Sensor → Board 1:   0x54 Data frames (UL, session key) — SUCCESS
```

## Quick Reference

### Channel Plan
```
UL CH1: 915.6 MHz  →  DL CH9:  920.4 MHz    (125 kHz → 500 kHz)
UL CH2: 915.8 MHz  →  DL CH10: 921.0 MHz
UL CH3: 916.0 MHz  →  DL CH11: 921.6 MHz
UL CH4: 916.2 MHz  →  DL CH12: 922.2 MHz
UL CH5: 916.4 MHz  →  DL CH13: 922.8 MHz
UL CH6: 916.6 MHz  →  DL CH14: 923.4 MHz
UL CH7: 916.8 MHz  →  DL CH15: 924.0 MHz
UL CH8: 917.0 MHz  →  DL CH16: 924.6 MHz
Beacon: 927.6 MHz (CH17)
```

### Radio Parameters
```
UL:  SF5, BW 125 kHz, CR 4/5, Preamble 12, Sync 0x1424 (private), CRC on
DL:  SF5, BW 500 kHz, CR 4/5, Preamble 12, Sync 0x1424 (private), CRC on
     invert_pol = false (confirmed from firmware RE)
```

### Keys
```
Pairing key: 47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe
```

### SSH Access
```
RPi (Board 1):  ssh -i ~/.ssh/id_ed25519_pi alex@10.1.1.87
RPi (Board 2):  ssh -i ~/.ssh/id_ed25519_pi alex@<NEW_IP>
Ubiquiti GW:    ssh ubnt@10.1.1.141  (password: webpass from Protect UI)
```

### Run Commands
```bash
# Board as gateway (TX mode)
python -m superlink.gateway --mac AA:BB:CC:DD:EE:FF --verbose --log pairing.csv

# Board as DL capture (passive)
python -m superlink.capture --dl-channel <9-16> --verbose

# Deploy code to RPi
rsync -avz --exclude='__pycache__' -e "ssh -i ~/.ssh/id_ed25519_pi" \
  tools/sx1302/superlink/ alex@<IP>:~/superlink/superlink/

# Run tests
ssh -i ~/.ssh/id_ed25519_pi alex@<IP> \
  "cd ~/superlink && source .venv/bin/activate && python -m pytest tests/ -v"
```

## Firmware RE Summary (from this session)

Key findings from Binary Ninja analysis of `lorabrd` (UP-Sense-Link gateway firmware):

1. **lorabrd is GATEWAY firmware**, not sensor firmware. It runs on the SX1302-based bridge.
2. **Discovery handler** (sub_51af2): Receives 0x40, checks sensor adoption status, calls sub_51742 directly to build and send 0x62 ConnectionRsp. No beacon prerequisite.
3. **Connection handler** (sub_524ac): Dispatches on inner_type: case 0 → ConnectionReq (sub_51914), case 2 → ChallengeReq (sub_52090).
4. **TX path** (sub_83528 → sub_826fc → sub_874ac/lgw_send): `invert_pol` is never set — stays false from memset. Confirmed non-inverted IQ for DL.
5. **Config parser** (sub_8138c): Per-channel config with `beacon_delay`, `dl_retry_delay`, `dwell_time`, `dwell_period`, `preamble` (default 12), `spread_factor`, `bandwidth`, `coderate`.
6. **Beacon infrastructure** exists: `LoRaBeacon::SyncSchedules`, `LoRaBeacon::ScheduleNextSync`, beacon on CH17. But discovery handler does NOT require beacon sync before responding.
