# OpenSuperLink

Open-source reverse engineering of Ubiquiti's proprietary SuperLink protocol — a LoRa-based sub-GHz radio system operating on 915 MHz (US ISM band).

> **Status: Early Research / Scaffolding** — No devices in hand yet. Collecting public information and building tooling.

## What is SuperLink?

SuperLink is Ubiquiti's proprietary long-range wireless protocol used across their UniFi ecosystem. It rides on top of standard **Semtech LoRa chirp spread spectrum (CSS) modulation** but uses a completely proprietary MAC layer, framing, encryption, and device management protocol. It is **not LoRaWAN-compatible**.

### Known Products Using SuperLink

| Product | Role | Notes |
|---------|------|-------|
| UDM-Pro / UDM-SE / UDM-Pro Max | Hub/Coordinator | Integrated SuperLink radio module |
| UniFi Express | Hub/Coordinator | Compact gateway with SuperLink |
| UniFi Access (UA-Hub, UA-Lite, UA-Pro) | Peripheral | Door access readers |
| UniFi Connect (Display, EV Station) | Peripheral | Digital signage, EV charging |
| UniFi SmartPower (USP-Plug, USP-Strip, USP-PDU) | Peripheral | Smart power devices |
| UniFi Building Bridge | Peripheral | Point-to-point sub-GHz links |

### Architecture

```
  [UniFi Gateway]          Star Topology
   SuperLink Hub    <--- 915 MHz LoRa --->  [UA-Pro Reader]
        |                                   [USP-Plug]
        |                                   [Connect Display]
   [UniFi Controller]                       [Building Bridge]
```

## What We Know So Far

### Physical Layer (Confirmed from FCC Internal Photos)
- **Modulation**: Semtech LoRa (CSS) — standard PHY
- **Frequency**: 902–928 MHz ISM band (US), FHSS across multiple channels
- **Transceiver**: **Semtech SX1262** (peripheral side — single-channel LoRa transceiver, +22 dBm)
- **Baseband**: **Semtech SX1302** (hub side — multi-channel digital baseband, 8 simultaneous RX channels)
- **RF Front-End**: **Skyworks SKY66420-11** (860–930 MHz FEM — PA + LNA + switch)
- **Bandwidth**: Likely 125 kHz or 500 kHz per channel
- **Spreading Factor**: Likely SF7–SF10
- **TX Power**: Up to +22 dBm

### MAC / Protocol Layer
- Proprietary framing (not LoRaWAN)
- Bidirectional communication with low latency
- Device discovery, pairing, and adoption via UniFi controller
- Low throughput (single-digit kbps) — control/status messages only

### Security
- AES encryption (per Ubiquiti marketing)
- Key exchange during adoption process
- Key derivation, auth handshake, session management — all unknown

### Hardware
- Hub devices: LoRa radio on daughter card/module connected to main SoC
- Peripheral devices: LoRa transceiver on main PCB
- FCC filings under grantee code **SWX** (e.g., SWX-UDMPRO, SWX-UDMSE)

## Project Structure

```
superlink/
├── docs/                   # Documentation
│   ├── fcc/                # FCC filings, test reports, internal photos
│   ├── teardowns/          # Hardware teardown notes and photos
│   ├── protocol/           # Protocol documentation as we decode it
│   └── captures/           # Annotated RF captures
├── tools/                  # Tooling
│   ├── sdr/                # SDR capture scripts (GNU Radio, etc.)
│   ├── decoder/            # Packet decoder / dissector
│   └── emulator/           # Protocol emulator for testing
├── firmware/               # Firmware analysis
│   ├── dumps/              # Extracted firmware images
│   └── analysis/           # Ghidra/IDA projects, notes
├── src/                    # Protocol implementation (as decoded)
│   ├── phy/                # Physical layer (LoRa demod/mod)
│   ├── mac/                # MAC layer framing
│   ├── crypto/             # Encryption / key exchange
│   └── transport/          # Higher-level protocol logic
├── tests/                  # Test suite
└── research/               # Research notes, links, references
```

## Reverse Engineering Plan

See [docs/RE_PLAN.md](docs/RE_PLAN.md) for the detailed phased approach.

## Related Work

- **[gr-lora](https://github.com/rpp0/gr-lora)** — GNU Radio LoRa demodulator (can decode raw LoRa symbols)
- **[LoRa-SDR](https://github.com/tapparelj/gr-lora_sdr)** — Alternative GNU Radio LoRa implementation
- **[RevSpace LoRa](https://revspace.nl/DecodingLora)** — LoRa PHY reverse engineering reference
- **[UniFi Inform Protocol](https://github.com/mcrute/ubnt-tools)** — Reverse engineered UniFi controller protocol (useful reference for Ubiquiti's patterns)

## Legal

This project is for **interoperability research** under applicable reverse engineering exemptions. All work is based on:
- Publicly available FCC filings
- Over-the-air RF captures (legal to receive under FCC Part 15)
- Published hardware teardowns
- Firmware analysis for interoperability purposes

## Contributing

This project is in its earliest stages. If you have access to SuperLink devices or relevant expertise, contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT — See [LICENSE](LICENSE)
