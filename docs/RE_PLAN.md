# SuperLink Reverse Engineering Plan

## Phase 0: Public Information Gathering (No Devices Needed)

**Goal**: Maximize knowledge from publicly available sources before spending money on hardware.

### 0.1 FCC Filing Analysis
- [ ] Pull all FCC filings under grantee code **SWX** for SuperLink-capable devices
- [ ] Extract internal photos — identify LoRa transceiver ICs, MCUs, antenna designs
- [ ] Review RF test reports for frequency hopping patterns, channel plans, power levels
- [ ] Document antenna characteristics and board layouts
- [ ] Key FCC IDs: SWX-UDMPRO, SWX-UDMSE, SWX-UALITE, SWX-UAPRO, SWX-USPPDU

### 0.2 Firmware Acquisition
- [ ] Check for publicly accessible firmware update URLs (Ubiquiti often hosts at dl.ui.com or fw-download.ubnt.com)
- [ ] Download firmware for all SuperLink-capable devices
- [ ] Attempt extraction with binwalk / ubi_reader / jefferson
- [ ] Identify filesystem layout, key binaries, libraries
- [ ] Look for the SuperLink daemon/service binary and configuration files

### 0.3 UniFi Controller Analysis
- [ ] Install UniFi Network Application (free download)
- [ ] Examine controller code for SuperLink-related APIs, configuration, and protocol definitions
- [ ] The controller is Java-based — decompile with jadx/cfr
- [ ] Look for protobuf definitions, JSON schemas, or other protocol descriptors
- [ ] Search for SuperLink-related strings, constants, channel definitions

### 0.4 Community Intelligence
- [ ] Search Ubiquiti Community forums for SuperLink technical discussions
- [ ] Check GitHub for any existing tools, scripts, or documentation
- [ ] Review Ubiquiti job postings for clues about technology stack
- [ ] Look for academic papers referencing Ubiquiti's LoRa implementation

---

## Phase 1: Hardware Acquisition & RF Capture

**Goal**: Capture raw SuperLink RF traffic and identify basic protocol structure.

### 1.1 Equipment Needed

**Option A: SDR Approach (Receive Only)**
- RTL-SDR v4 or HackRF One (~$20–$300)
- 915 MHz antenna (tuned for ISM band)
- GNU Radio + gr-lora for LoRa demodulation

**Option B: LoRa Dev Board (Receive + Transmit)**
- Heltec LoRa 32 v3 (SX1262-based, ~$15)
- or Adafruit Feather M0 RFM96 (SX1276-based, ~$35)
- Custom firmware for raw packet capture / promiscuous mode

**Option C: Commercial LoRa Sniffer**
- Semtech SX1262 evaluation kit
- Can be configured for raw packet capture

**SuperLink Devices (minimum viable set):**
- UniFi Express (cheapest hub with SuperLink, ~$150)
- USP-Plug (cheapest peripheral, ~$30)
- This gives us a hub + peripheral pair to capture traffic between

### 1.2 Initial RF Capture
- [ ] Set up wideband capture of 902–928 MHz band
- [ ] Power on SuperLink devices and capture discovery/pairing traffic
- [ ] Identify channel hopping pattern and dwell times
- [ ] Capture steady-state (idle) traffic — beacons, keepalives
- [ ] Capture event-triggered traffic — state changes, commands
- [ ] Save raw IQ captures for later analysis

### 1.3 LoRa PHY Decoding
- [ ] Use gr-lora or LoRa dev board to demodulate captures
- [ ] Identify LoRa parameters: SF, BW, CR, preamble length, sync word
- [ ] The **sync word** is key — Ubiquiti likely uses a custom sync word (not 0x12 for LoRaWAN or 0x34 for private LoRa)
- [ ] Determine if all channels use the same LoRa parameters or if they vary
- [ ] Extract raw payload bytes from demodulated frames

---

## Phase 2: Protocol Dissection

**Goal**: Understand the proprietary MAC layer and frame structure.

### 2.1 Frame Structure Analysis
- [ ] Collect large corpus of decoded frames (hundreds+)
- [ ] Identify fixed vs. variable fields through statistical analysis
- [ ] Map out frame header: preamble, length, type, addressing, flags
- [ ] Identify frame types: beacon, data, ack, join-request, join-accept, etc.
- [ ] Determine addressing scheme (device IDs, network IDs)
- [ ] Locate payload boundaries and any FCS/CRC fields

### 2.2 Protocol State Machine
- [ ] Map the device lifecycle: discovery → pairing → adoption → active → idle
- [ ] Capture and annotate the full adoption sequence
- [ ] Identify keepalive/heartbeat intervals and format
- [ ] Document command/response patterns
- [ ] Determine if there's TDMA, polling, or random access at the MAC layer

### 2.3 Cross-Reference with Firmware
- [ ] Reverse engineer the SuperLink binary from firmware (Ghidra/IDA)
- [ ] Identify packet construction and parsing functions
- [ ] Map firmware constants to observed protocol fields
- [ ] Look for protocol version numbers, capability negotiation
- [ ] Identify error handling and edge cases

---

## Phase 3: Cryptanalysis

**Goal**: Understand the encryption and authentication mechanisms.

### 3.1 Encryption Identification
- [ ] Determine which fields are encrypted vs. plaintext
- [ ] Identify the encryption algorithm (likely AES-128 or AES-256 based on marketing)
- [ ] Determine the mode of operation (CBC, CTR, GCM, CCM*)
- [ ] Identify IV/nonce construction
- [ ] Look for MIC/MAC (Message Integrity Code) fields

### 3.2 Key Management
- [ ] Reverse engineer key derivation from firmware
- [ ] Identify the key exchange during adoption (likely involves controller)
- [ ] Determine if there are network keys, session keys, device keys
- [ ] Check if keys are derived from device-specific info (MAC address, serial, etc.)
- [ ] Assess key rotation mechanisms

### 3.3 Authentication
- [ ] Understand device authentication during join/rejoin
- [ ] Identify any challenge-response mechanisms
- [ ] Determine if mutual authentication is performed
- [ ] Look for replay protection (frame counters, timestamps)

---

## Phase 4: Implementation

**Goal**: Build an open-source SuperLink stack.

### 4.1 Packet Decoder / Wireshark Dissector
- [ ] Build a protocol dissector (Wireshark Lua plugin or standalone)
- [ ] Decode all identified frame types
- [ ] Display human-readable field interpretations
- [ ] Support pcap import from SDR captures

### 4.2 Reference Implementation
- [ ] Implement PHY layer interface (SX1262 driver)
- [ ] Implement MAC layer framing (encode/decode)
- [ ] Implement crypto layer (with known keys)
- [ ] Implement basic protocol state machine
- [ ] Target platform: ESP32 + SX1262 (common, cheap LoRa dev boards)

### 4.3 Interoperability Testing
- [ ] Test decoder against live SuperLink traffic
- [ ] Verify frame construction matches real devices
- [ ] Test adoption flow with a real UniFi controller
- [ ] Validate crypto implementation against captured encrypted frames

---

## Phase 5: Tooling & Community

**Goal**: Make the project accessible and useful.

### 5.1 Capture Tools
- [ ] GNU Radio flowgraph for SuperLink capture
- [ ] LoRa dev board firmware for packet sniffing
- [ ] Automated capture + decode pipeline

### 5.2 Documentation
- [ ] Complete protocol specification document
- [ ] Hardware setup guides
- [ ] Tutorial: capturing your first SuperLink packet

### 5.3 Applications
- [ ] Custom SuperLink peripheral (e.g., sensor node that reports to UniFi)
- [ ] SuperLink gateway bridge (SuperLink ↔ MQTT/HTTP)
- [ ] Integration with Home Assistant or similar platforms

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Strong encryption with no key extraction path | Blocks Phase 3+ | Focus on firmware RE for key material; check for hardcoded/default keys |
| Firmware is encrypted/signed | Blocks Phase 0.2 | Try UART/JTAG extraction from hardware; check for older unencrypted versions |
| LoRa parameters change dynamically | Complicates capture | Wideband SDR capture first, then narrow down |
| Protocol updates in firmware | Moving target | Pin analysis to specific firmware versions |
| Legal challenges | Project viability | Stay within interoperability exemptions; receive-only initially |

## Priority: What to Do First

1. **FCC filings** — free, immediate, high information density
2. **Firmware download & extraction** — free, can be done now
3. **UniFi controller decompilation** — free, may reveal protocol structure
4. **Buy minimum hardware** (UniFi Express + USP-Plug + SDR/LoRa board)
5. **First RF capture** — confirms everything above
