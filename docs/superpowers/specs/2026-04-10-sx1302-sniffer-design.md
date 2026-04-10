# SX1302 SuperLink Sniffer — Design Spec

## Overview

Python CLI tool running on RPi 4B with SX1302 CoreCell. Receives SuperLink packets on all 8 UL channels simultaneously, decodes frames, optionally decrypts with a provided session key, and interprets payload contents. Replaces the single-channel Heltec sniffer + serial decoder workflow with a self-contained tool.

## Architecture

Three layers, bottom to top:

```
CLI (cli.py)           — interactive terminal, filtering, display
Decoder (decoder.py)   — frame parsing, crypto, payload interpretation
HAL driver (hal.py)    — ctypes wrapper around libloragw.a
```

No network, no external services. Everything runs locally on the RPi.

## HAL Driver (`hal.py`)

ctypes wrapper around `libloragw`. The HAL builds as a static library (`libloragw.a`), but ctypes requires a shared library. We compile a `.so` from the static lib and its dependencies:

```bash
gcc -shared -o libloragw.so \
    -Wl,--whole-archive libloragw.a -Wl,--no-whole-archive \
    -L../libtools -ltinymt32 -lrt -lm
```

This `.so` is what `hal.py` loads via `ctypes.CDLL()`.

### C Structs to Mirror

- `struct lgw_conf_board_s` — com_type, com_path, lorawan_public, clksrc, full_duplex
- `struct lgw_conf_rxrf_s` — enable, freq_hz, rssi_offset, type, tx_enable, single_input_mode
- `struct lgw_conf_rxif_s` — enable, rf_chain, freq_hz (IF offset), datarate
- `struct lgw_pkt_rx_s` — freq_hz, if_chain, status (CRC), payload[256], size, modulation, datarate, coderate, rssi, snr, count_us, bandwidth

### Functions to Wrap

| C function | Purpose |
|------------|---------|
| `lgw_board_setconf` | Board config (SPI, sync word) |
| `lgw_rxrf_setconf` | Radio config (center freq, type, RSSI offset) |
| `lgw_rxif_setconf` | IF channel config (rf_chain, IF offset) |
| `lgw_start` | Start concentrator |
| `lgw_stop` | Stop concentrator |
| `lgw_receive` | Fetch received packets |
| `lgw_get_instcnt` | Internal counter (timestamping) |

### Hardcoded SuperLink Config

The wrapper applies the SuperLink channel plan internally:

- Radio A: 916.0 MHz (SX1250), radio B: 917.0 MHz (SX1250)
- 8 IF channels mapping to UL 915.6-917.0 MHz (200 kHz spacing)
- `lorawan_public = false` (sync word 0x1424)
- Mode 0 channel layout: radio 1 IF {-400k, -200k, 0}, radio 0 IF {-400k, -200k, 0, +200k, +400k}
- SPI path: `/dev/spidev0.0`

### GPIO Reset

The wrapper calls `reset_lgw.sh start` via `os.system()` before `lgw_start()`, matching the HAL's convention. The reset script uses `pinctrl` (RPi native GPIO tool).

### Python Interface

```python
@dataclass
class RxPacket:
    freq_hz: int
    channel: int        # 0-7 (IF chain)
    rssi: float
    snr: float
    crc_ok: bool
    payload: bytes
    timestamp_us: int   # SX1302 internal counter

class SX1302:
    def __init__(self, spi_path="/dev/spidev0.0"):
        ...
    def start(self) -> None:
        ...
    def stop(self) -> None:
        ...
    def receive(self) -> list[RxPacket]:
        ...
```

## Decoder (`decoder.py`)

Pure Python. No HAL dependency — operates on raw bytes.

### Frame Parser

Input: raw bytes (from `RxPacket.payload`).

```
Offset  Size  Field
0       1     Mctrl
1       1     Dctrl
2       6     MAC address
8       1     SeqHi (frame counter)
9       1     SeqLo (nonce component)
10      4     MIC (BLAKE2b truncated)
14      N     Encrypted payload (if present)
```

Minimum frame: 14 bytes. Payload length = total - 14.

Output:
```python
@dataclass
class SuperLinkFrame:
    mctrl: int
    dctrl: int
    mac: bytes          # 6 bytes
    seq_hi: int
    seq_lo: int
    mic: bytes          # 4 bytes
    payload_raw: bytes  # encrypted
    payload: bytes | None     # decrypted (if key provided)
    mic_valid: bool | None    # MIC check result (if key provided)
    interpretation: dict | None  # parsed payload fields
```

### Known Dctrl Values

| Value | Direction | Meaning | Typical size |
|-------|-----------|---------|-------------|
| 0x54  | UL | Data | 19B (5B payload) |
| 0x44  | UL | Data extended | 20B (6B payload) |
| 0x63  | DL | Response/ack | 16B (2B payload) |
| 0x74  | DL | Ack | TBD |

### Decryption

When a session key is provided (32 bytes hex):

1. Build 24-byte XSalsa20 nonce:
   ```
   nonce = [mctrl, dctrl, MAC[0:6], seq_hi, seq_lo, 0x00 * 14]
   ```

2. Decrypt payload:
   ```python
   decrypted = pysodium.crypto_stream_xor(payload_raw, nonce, key)
   ```

3. Verify MIC (BLAKE2b):
   ```python
   mic_input = header_bytes[0:10] + decrypted
   computed_mic = pysodium.crypto_generichash(mic_input, key=session_key, outlen=4)
   mic_valid = (computed_mic == mic)
   ```

### Payload Interpretation

For decrypted data frames (dctrl 0x54, 0x44):

```
Byte 0: Type (0x0C = sensor report)
Byte 1: Flags
Byte 2: Command (0x0F = door state)
Byte 3: Sub-command
Byte 4+: Data
```

Known interpretations:
- Type 0x0C, Cmd 0x0F: Door sensor — data 0x00=OPEN, 0x01=CLOSED
- Extended frames (~every 16th): battery level (0x64=100%), uptime counter

## CLI (`cli.py`)

### Invocation

```bash
superlink-sniff                          # sniff, no decryption
superlink-sniff --key <64-hex-chars>     # sniff with decryption
superlink-sniff --mac 90:41:B2:2E:9A:53 # filter by device
superlink-sniff --log capture.csv        # log to file
```

### Live Output Format

```
14:23:01.442  CH3 UL  90:41:B2:2E:9A:53  seq=5B.11  19B  -32dBm  8.2dB
  dctrl=54 data   MIC=9CFFC24C ok   0C 00 0F 00 01  DOOR CLOSED

14:23:01.890  CH3 DL  90:41:B2:2E:9A:53  seq=A2.9A  16B
  dctrl=63 ack    MIC=3B22A1F0 ok   22 01
```

Color coding (ANSI):
- Green: UL packets
- Blue: DL packets
- Red: CRC errors or MIC failures
- Yellow: encrypted (no key provided)
- Dim: filtered-out packets (if verbose mode)

### Filtering

- `--mac MAC` — show only packets to/from this MAC
- `--ul` / `--dl` — show only uplink / downlink
- `--channel N` — show only specific channel (1-8)
- `--raw` — show full hex dump of every packet

### Logging

- `--log FILE.csv` — append decoded packets as CSV rows:
  `timestamp, channel, direction, mac, seq, rssi, snr, crc, dctrl, mic_valid, payload_hex, interpretation`

### Stats

Ctrl-S (or `--stats` flag) prints summary:
- Total packets by device MAC
- Packets per channel
- CRC error rate
- Average RSSI/SNR per device

### Keyboard Commands

While running:
- `q` — quit cleanly (lgw_stop)
- `s` — print stats
- `f` — toggle MAC filter interactively
- `h` — help

## File Layout

Installed on the RPi at `~/superlink/`:

```
superlink/
    __init__.py
    hal.py          — ctypes wrapper for libloragw
    decoder.py      — frame parsing, crypto, payload interpretation
    cli.py          — CLI entry point
superlink-sniff     — entry script (calls cli.main())
```

## Dependencies

**Python packages** (installed in venv):
- `pysodium` — libsodium bindings for XSalsa20 + BLAKE2b

**System packages** (apt):
- `libsodium-dev` — required by pysodium
- `python3-venv` — for venv creation

**Build artifacts** (already present):
- `~/sx1302_hal/libloragw/libloragw.a` — compiled HAL static library (relinked as `.so` for ctypes)
- `~/sx1302_hal/libloragw/inc/` — HAL headers (reference for struct layouts)
- `~/sx1302_hal/libtools/libbase64.a`, `libtinymt32.a` — HAL dependencies

## Out of Scope

- TX / packet injection (phase 2)
- DL channel listening (requires radio retune — phase 2)
- Automated key derivation / connection state machine
- Wireshark dissector / pcap export
- Web UI or remote access
- Beacon channel monitoring
