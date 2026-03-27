# SuperLink Hardware Components

## Identified ICs (from FCC Internal Photos)

### RF Front-End
- **Skyworks SKY66420-11** — 860–930 MHz RF Front-End Module
  - Integrates PA (power amplifier), LNA (low noise amplifier), and TX/RX switch
  - Designed specifically for LoRa / sub-GHz ISM applications
  - Provides ~+20 dBm output power with high efficiency
  - [Datasheet](https://www.skyworksinc.com/products/front-end-modules/sky66420-11)

### LoRa Transceiver
- **Semtech SX1262** — Long Range Low Power LoRa Transceiver
  - +22 dBm max TX power
  - Global frequency coverage (150–960 MHz)
  - LoRa + (G)FSK modulation
  - SPI interface to host MCU
  - Successor to SX1276 with better power consumption and sensitivity
  - [Product Page](https://www.semtech.com/products/wireless-rf/lora-connect/sx1262)

### Baseband / Gateway Chip
- **Semtech SX1302** — LoRa Core Digital Baseband Chip
  - Designed for LoRaWAN gateway applications
  - Can demodulate multiple LoRa channels simultaneously
  - 8 uplink channels + 1 downlink channel
  - Multiple SF demodulation on each channel
  - **Interesting**: This is a gateway-class chip, suggesting the hub side may be able to listen on multiple channels/SFs simultaneously
  - [Product Page](https://www.semtech.com/products/wireless-rf/lora-core/sx1302)

## Architecture Implications

The presence of the **SX1302** is significant:
- It's a multi-channel receiver — the hub can listen on multiple frequencies and spreading factors at once
- This is the same chip used in LoRaWAN gateways
- Peripherals likely use just the **SX1262** (single channel TX/RX)
- The hub coordinates channel assignments and hopping

```
Hub Side (UDM-Pro, etc.):
  SX1302 (multi-channel baseband) → SKY66420-11 (RF front-end) → Antenna

Peripheral Side (USP-Plug, UA-Pro, etc.):
  SX1262 (single-channel transceiver) → SKY66420-11 (RF front-end) → Antenna
```

## TODO
- [ ] Identify the host MCU on the SuperLink radio module
- [ ] Check for debug headers (UART, SWD/JTAG) on the radio module PCB
- [ ] Document antenna type and connector (PCB trace, U.FL, SMA)
- [ ] Get specific FCC ID photos linked here for each device
