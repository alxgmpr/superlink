# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenSuperLink is a reverse engineering project for Ubiquiti's proprietary SuperLink protocol — a LoRa-based sub-GHz radio system (915 MHz US ISM band). The project is in early research/scaffolding phase. The goal is interoperability research under applicable RE exemptions.

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

## Repository Structure

- `docs/protocol/` — Decoded protocol specs (frame format, crypto, pairing, channel plan). This is the primary knowledge base from firmware RE.
- `docs/teardowns/` — Hardware component identification from FCC photos
- `tools/sniffer/` — PlatformIO project: ESP32-S3 + SX1262 LoRa packet sniffer with OLED display. Single-file firmware at `src/main.cpp`.
- `tools/decoder/` — Placeholder for packet decoder/Wireshark dissector
- `tools/sdr/` — GNU Radio capture setup notes
- `firmware/dumps/` — Extracted firmware images (gitignored, copyrighted)
- `research/` — Research task tracking, phase 0 info gathering
- `src/` — Future protocol implementation (phy, mac, crypto, transport layers — currently empty)
- `tests/` — Future test suite (currently empty)
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
