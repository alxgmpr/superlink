# GNU Radio SuperLink Capture Setup

## Prerequisites

```bash
# Install GNU Radio
brew install gnuradio  # macOS
# or: apt install gnuradio  # Linux

# Install gr-lora (LoRa demodulator)
git clone https://github.com/rpp0/gr-lora.git
cd gr-lora && mkdir build && cd build
cmake .. && make && sudo make install

# Alternative: gr-lora_sdr (newer, actively maintained)
git clone https://github.com/tapparelj/gr-lora_sdr.git
cd gr-lora_sdr && mkdir build && cd build
cmake .. && make && sudo make install
```

## Wideband Capture (Step 1)

Capture the full 902–928 MHz band to identify active channels:

```bash
# Using RTL-SDR (limited to ~2.4 MHz bandwidth — need to sweep)
# Using HackRF (20 MHz bandwidth — can cover most of the band)
# Using USRP (up to 56 MHz — can cover entire band at once)
```

## Known LoRa Parameters to Try

Based on the SX1262/SX1302 datasheets and common configurations:

| Parameter | Values to Try |
|-----------|---------------|
| Bandwidth | 125 kHz, 250 kHz, 500 kHz |
| Spreading Factor | SF7, SF8, SF9, SF10, SF11, SF12 |
| Coding Rate | 4/5, 4/6, 4/7, 4/8 |
| Sync Word | 0x12 (LoRaWAN public), 0x34 (LoRa private), 0x?? (Ubiquiti custom) |
| Preamble Length | 6, 8, 12 symbols |

## Channel Plan Hypothesis

FCC Part 15.247 FHSS requirements for 902–928 MHz:
- Minimum 50 hopping channels if dwell time > 400ms
- Minimum 25 hopping channels if dwell time ≤ 400ms
- Maximum 400ms dwell time per channel

With 500 kHz bandwidth: ~52 channels in 26 MHz band
With 125 kHz bandwidth: ~200 channels in 26 MHz band

The SX1302 supports 8 simultaneous receive channels, which aligns well with a
hub that listens on 8 frequencies while peripherals hop among them.
