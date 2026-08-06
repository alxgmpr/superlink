# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

superlink2mqtt is an open gateway that bridges Ubiquiti SuperLink sensors onto MQTT (with Home Assistant discovery), built on reverse engineering of Ubiquiti's proprietary SuperLink protocol — a LoRa-based sub-GHz radio system (915 MHz US ISM band). Pairing and adoption work end-to-end against real sensors via a Pi-based gateway (Curve25519 DH → BLAKE2b KDF → XSalsa20-Poly1305 DL frames). The RE side is interoperability research under applicable RE exemptions.

SuperLink uses standard Semtech LoRa PHY (SX1262 peripherals, SX1302 gateway baseband) but a completely proprietary MAC layer with libsodium-based encryption (XSalsa20-Poly1305, Curve25519 DH key exchange, BLAKE2b KDF).

## Key Protocol Facts (from firmware RE)

- **LoRa params**: SF5, 125 kHz UL / 500 kHz DL, coding rate 4/5, sync word 0x1424 (standard private LoRa)
- **8 UL channels** (915.6–917.0 MHz) paired with **8 DL channels** (920.4–924.6 MHz), beacon on 927.6 MHz
- **Frame format**: 10-byte cleartext header (Mctrl, Dctrl, 6-byte MAC, 2-byte seq) + 4-byte BLAKE2b integrity + encrypted payload
- **Crypto**: Curve25519 ECDH for session keys, XSalsa20-Poly1305 for authenticated encryption, XSalsa20 for streaming data
- **Hardcoded default pairing key** documented in `docs/protocol/crypto_and_pairing.md`
- **Source binary**: `lorabrd` (ubnt-lora-bridge) from UP-Sense-Link firmware

## Build Commands

### LoRa Sniffer (Heltec V3)

Uses PlatformIO. The venv at `.venv/` has `platformio` installed.

```bash
source .venv/bin/activate
cd tools/sniffer
pio run                    # compile
pio run -t upload          # flash to Heltec V3
pio device monitor         # serial monitor at 115200 baud
```

### Python Tools

```bash
source .venv/bin/activate
# venv has: ubi_reader, pyserial, platformio
```

### Tests

```bash
source .venv/bin/activate
pytest tests/           # conftest.py adds tools/sx1302 to sys.path for `import superlink.*`
```

### Pi Gateway / Sniffer (SX1302)

Runs on a Raspberry Pi with SX1302 CoreCell. First-time setup on the Pi: `tools/sx1302/setup_rpi.sh`.

```bash
cd tools/sx1302
./deploy.sh              # rsync to Pi
./deploy.sh run gw       # deploy + run gateway state machine (pairs with real sensor)
./deploy.sh run          # deploy + run sniffer CLI
```

Entry scripts on the Pi: `superlink-sniff` (CLI → `superlink.cli:main`), `superlink-gw` (gateway state machine → `superlink.gateway:main`).

### Session Key Capture (real gateway)

```bash
tools/keyhook/capture_key.sh [gateway_ip]   # cross-compiles LD_PRELOAD hook, deploys to gateway, prints session key
```

Requires `arm-linux-gnueabihf-gcc` and `sshpass`. Gateway SSH creds and default pairing key live in `docs/protocol/crypto_keys_captured.md`.

## Repository Structure

- `docs/protocol/` — Decoded protocol specs (frame format, crypto, pairing, channel plan). This is the primary knowledge base from firmware RE.
- `docs/teardowns/` — Hardware component identification from FCC photos
- `tools/sniffer/` — PlatformIO project: ESP32-S3 + SX1262 LoRa packet sniffer with OLED display. Single-file firmware at `src/main.cpp`.
- `tools/sx1302/` — Pi + SX1302 concentrator gateway. Python package `superlink/` (hal, decoder, crypto, gateway state machine, cli) plus entry scripts `superlink-sniff`, `superlink-gw` and `deploy.sh`. This is the active development target.
- `tools/keyhook/` — `LD_PRELOAD` shim (`keyhook.c` → `keyhook.so`) that captures session keys from a running `lorabrd` on the real gateway. Deployed via `capture_key.sh`.
- `tools/emulator/` — sensor-side emulator scaffolding (empty)
- `tools/decoder/` — Placeholder for packet decoder/Wireshark dissector
- `tools/sdr/` — GNU Radio capture setup notes
- `firmware/dumps/` — Extracted firmware images (gitignored, copyrighted)
- `research/` — Research task tracking, phase 0 info gathering
- `src/` — Reserved for protocol library (phy/mac/crypto/transport dirs exist but empty; real implementation currently lives in `tools/sx1302/superlink/`)
- `tests/` — pytest suite: `test_crypto.py`, `test_decoder.py`, `test_gateway.py`, `test_hal.py`, plus `fixtures/captured_frames.py`
- `captures/` — OTA log captures from live sensor/gateway sessions (gitignored live subdir)
- `docs/RE_PLAN.md` — 5-phase reverse engineering roadmap

## Sniffer Serial Commands

The sniffer accepts single-char commands over serial:
- `u/d/a` — scan UL only / DL only / all channels
- `1-8` — park on UL channel 1-8
- `!@#$%^&*` (Shift+1-8) — park on DL channel 9-16
- `b` — park on beacon channel (927.6 MHz)
- `s` — status, `h` — help

## Firmware Analysis

Binary analysis uses Ghidra. Key binary is `lorabrd` from the UP-Sense-Link firmware. C++ RTTI symbols reveal the namespace hierarchy: `ubnt::lorapack::phypayload`, `ubnt::lorapack::connection`, `ubnt::lorapack::management`. See `docs/protocol/protocol_structure.md` for the full class hierarchy.
