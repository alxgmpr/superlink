# Contributing to superlink2mqtt

## How You Can Help

### No Hardware Needed
- **FCC filing analysis** — Pull internal photos and test reports from FCC filings
- **Firmware analysis** — Download and extract Ubiquiti firmware images
- **Controller decompilation** — Analyze the UniFi Network Application for protocol clues
- **Documentation** — Organize findings, improve docs

### With Hardware
- **RF captures** — Record SuperLink traffic with SDR or LoRa dev boards
- **Protocol analysis** — Help decode captured frames
- **Firmware extraction** — UART/JTAG dumps from devices
- **Testing** — Validate protocol implementations against real hardware

## Submitting Findings

1. Open an issue describing what you found
2. Include evidence (screenshots, hex dumps, captures)
3. Reference the specific device model and firmware version
4. For RF captures, include the raw IQ or decoded LoRa frames

## Code Contributions

- Follow existing code style
- Include tests where applicable
- Document any protocol fields or behaviors you've identified
- Reference the relevant section of RE_PLAN.md

## Legal Guidelines

- Only work with legally obtained materials (OTA captures, public FCC filings, purchased hardware)
- Do not distribute copyrighted firmware images — share analysis and findings instead
- Do not circumvent access controls beyond what's needed for interoperability
- All contributions must be your own work or properly attributed
