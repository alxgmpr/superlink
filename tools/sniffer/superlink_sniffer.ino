/*
 * SuperLink LoRa Sniffer for Heltec LoRa 32 V3 (SX1262)
 *
 * Configures the radio for SuperLink parameters (SF5, 125kHz, private sync word)
 * and dumps any received packets to serial. Cycles through all 8 uplink channels
 * and the beacon channel.
 *
 * Hardware: Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262)
 * Library:  RadioLib (https://github.com/jgromes/RadioLib)
 *
 * Install RadioLib via Arduino Library Manager or PlatformIO.
 *
 * Board settings in Arduino IDE:
 *   Board: "Heltec WiFi LoRa 32 (V3)"
 *   Upload Speed: 921600
 *   USB CDC On Boot: Enabled
 */

#include <RadioLib.h>

// Heltec V3 SX1262 pin definitions
#define LORA_SS    8
#define LORA_DIO1  14
#define LORA_RST   12
#define LORA_BUSY  13

SX1262 radio = new Module(LORA_SS, LORA_DIO1, LORA_RST, LORA_BUSY);

// ═══════════════════════════════════════════════════════════════
// SuperLink Protocol Parameters (from firmware RE)
// ═══════════════════════════════════════════════════════════════

// Sync word: standard private LoRa (0x1424)
// RadioLib uses the 1-byte shorthand: 0x12
#define SUPERLINK_SYNC_WORD  0x12

// Spreading factor 5 (Semtech extension, not standard LoRaWAN)
#define SUPERLINK_SF  5

// Uplink: 125 kHz, Downlink: 500 kHz
#define SUPERLINK_BW_UL  125.0
#define SUPERLINK_BW_DL  500.0

// Coding rate 4/5 (default, unconfirmed)
#define SUPERLINK_CR  5

// Uplink channels (125 kHz, SF5) - sensor → gateway
const float UL_CHANNELS[] = {
  915.6, // CH1  → paired with DL CH9
  915.8, // CH2  → paired with DL CH10
  916.0, // CH3  → paired with DL CH11
  916.2, // CH4  → paired with DL CH12
  916.4, // CH5  → paired with DL CH13
  916.6, // CH6  → paired with DL CH14
  916.8, // CH7  → paired with DL CH15
  917.0, // CH8  → paired with DL CH16
};
#define NUM_UL_CHANNELS 8

// Downlink channels (500 kHz, SF5) - gateway → sensor
const float DL_CHANNELS[] = {
  920.4, // CH9
  921.0, // CH10
  921.6, // CH11
  922.2, // CH12
  922.8, // CH13
  923.4, // CH14
  924.0, // CH15
  924.6, // CH16
};
#define NUM_DL_CHANNELS 8

// Beacon / standalone downlink channel
#define BEACON_CHANNEL  927.6  // CH17, 500 kHz

// ═══════════════════════════════════════════════════════════════
// Sniffer Configuration
// ═══════════════════════════════════════════════════════════════

// How long to listen on each channel before hopping (ms)
#define DWELL_TIME_MS  2000

// Which channels to scan
enum ScanMode {
  SCAN_UL_ONLY,      // Only uplink channels (sensor → gateway)
  SCAN_DL_ONLY,      // Only downlink channels (gateway → sensor)
  SCAN_ALL,          // All channels including beacon
  SCAN_SINGLE,       // Park on one channel (set SINGLE_FREQ below)
};

ScanMode scanMode = SCAN_UL_ONLY;
float singleFreq = 916.0;  // For SCAN_SINGLE mode
float singleBW = 125.0;

// ═══════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════

volatile bool rxFlag = false;
int currentChannel = 0;
unsigned long lastHopTime = 0;
unsigned long totalPackets = 0;

void setRxFlag(void) {
  rxFlag = true;
}

// ═══════════════════════════════════════════════════════════════
// Setup
// ═══════════════════════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  while (!Serial && millis() < 3000);

  Serial.println();
  Serial.println("╔══════════════════════════════════════╗");
  Serial.println("║   OpenSuperLink LoRa Sniffer v0.1   ║");
  Serial.println("║   Heltec LoRa 32 V3 (SX1262)        ║");
  Serial.println("╚══════════════════════════════════════╝");
  Serial.println();

  // Initialize SX1262
  Serial.print("[SX1262] Initializing... ");
  int state = radio.begin(
    UL_CHANNELS[0],       // frequency (MHz)
    SUPERLINK_BW_UL,      // bandwidth (kHz)
    SUPERLINK_SF,          // spreading factor
    SUPERLINK_CR,          // coding rate (4/x)
    SUPERLINK_SYNC_WORD,   // sync word
    10,                    // output power (dBm) - doesn't matter for RX
    8,                     // preamble length
    0,                     // TCXO voltage (0 = don't use TCXO)
    false                  // use LDO regulator
  );

  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("FAILED, code ");
    Serial.println(state);
    while (true) { delay(1000); }
  }
  Serial.println("OK");

  // Set sync word explicitly (RadioLib may need the 2-byte version for SX1262)
  // 0x12 private LoRa = register value 0x1424
  radio.setSyncWord(SUPERLINK_SYNC_WORD);

  // Enable CRC (SuperLink likely uses it)
  radio.setCRC(true);

  // Set DIO1 as interrupt for RX done
  radio.setDio1Action(setRxFlag);

  printConfig();

  // Start receiving
  Serial.println("[RX] Starting continuous receive...");
  Serial.println();
  state = radio.startReceive();
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("[RX] startReceive failed, code ");
    Serial.println(state);
  }

  lastHopTime = millis();
}

// ═══════════════════════════════════════════════════════════════
// Main Loop
// ═══════════════════════════════════════════════════════════════

void loop() {
  // Check for received packet
  if (rxFlag) {
    rxFlag = false;
    handlePacket();
  }

  // Channel hopping (skip if SCAN_SINGLE)
  if (scanMode != SCAN_SINGLE && (millis() - lastHopTime > DWELL_TIME_MS)) {
    hopChannel();
    lastHopTime = millis();
  }

  // Serial command handler
  if (Serial.available()) {
    handleCommand(Serial.read());
  }
}

// ═══════════════════════════════════════════════════════════════
// Packet Handler
// ═══════════════════════════════════════════════════════════════

void handlePacket() {
  uint8_t buf[256];
  int len = radio.getPacketLength();

  if (len <= 0 || len > (int)sizeof(buf)) {
    radio.startReceive();
    return;
  }

  int state = radio.readData(buf, len);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("[RX] readData error: ");
    Serial.println(state);
    radio.startReceive();
    return;
  }

  totalPackets++;

  float rssi = radio.getRSSI();
  float snr = radio.getSNR();

  // Print packet header
  Serial.print("[PKT #");
  Serial.print(totalPackets);
  Serial.print("] ");
  Serial.print(getChannelName());
  Serial.print(" | len=");
  Serial.print(len);
  Serial.print(" | RSSI=");
  Serial.print(rssi, 1);
  Serial.print(" | SNR=");
  Serial.print(snr, 1);
  Serial.println();

  // Hex dump
  Serial.print("  HEX: ");
  for (int i = 0; i < len; i++) {
    if (buf[i] < 0x10) Serial.print("0");
    Serial.print(buf[i], HEX);
    if (i < len - 1) Serial.print(" ");
  }
  Serial.println();

  // Parse SuperLink header (first 10 bytes)
  if (len >= 14) {
    uint8_t mctrl = buf[0];
    uint8_t dctrl = buf[1];
    uint8_t mac[6];
    memcpy(mac, &buf[2], 6);
    uint16_t field8 = (buf[8] << 8) | buf[9];
    uint8_t integrity[4];
    memcpy(integrity, &buf[10], 4);

    Serial.print("  HDR: mctrl=0x");
    Serial.print(mctrl, HEX);
    Serial.print(" dctrl=0x");
    Serial.print(dctrl, HEX);
    Serial.print(" mac=");
    for (int i = 0; i < 6; i++) {
      if (mac[i] < 0x10) Serial.print("0");
      Serial.print(mac[i], HEX);
      if (i < 5) Serial.print(":");
    }
    Serial.print(" seq=0x");
    Serial.print(field8, HEX);
    Serial.print(" mic=");
    for (int i = 0; i < 4; i++) {
      if (integrity[i] < 0x10) Serial.print("0");
      Serial.print(integrity[i], HEX);
    }
    Serial.println();

    // Payload after 14-byte header
    if (len > 14) {
      Serial.print("  PAY: ");
      for (int i = 14; i < len; i++) {
        if (buf[i] < 0x10) Serial.print("0");
        Serial.print(buf[i], HEX);
        if (i < len - 1) Serial.print(" ");
      }
      Serial.println();
    }
  }

  Serial.println();

  // Restart receive
  radio.startReceive();
}

// ═══════════════════════════════════════════════════════════════
// Channel Hopping
// ═══════════════════════════════════════════════════════════════

void hopChannel() {
  float freq;
  float bw;

  switch (scanMode) {
    case SCAN_UL_ONLY:
      currentChannel = (currentChannel + 1) % NUM_UL_CHANNELS;
      freq = UL_CHANNELS[currentChannel];
      bw = SUPERLINK_BW_UL;
      break;

    case SCAN_DL_ONLY:
      currentChannel = (currentChannel + 1) % NUM_DL_CHANNELS;
      freq = DL_CHANNELS[currentChannel];
      bw = SUPERLINK_BW_DL;
      break;

    case SCAN_ALL: {
      int totalCh = NUM_UL_CHANNELS + NUM_DL_CHANNELS + 1;
      currentChannel = (currentChannel + 1) % totalCh;
      if (currentChannel < NUM_UL_CHANNELS) {
        freq = UL_CHANNELS[currentChannel];
        bw = SUPERLINK_BW_UL;
      } else if (currentChannel < NUM_UL_CHANNELS + NUM_DL_CHANNELS) {
        freq = DL_CHANNELS[currentChannel - NUM_UL_CHANNELS];
        bw = SUPERLINK_BW_DL;
      } else {
        freq = BEACON_CHANNEL;
        bw = SUPERLINK_BW_DL;
      }
      break;
    }

    case SCAN_SINGLE:
    default:
      return;
  }

  radio.standby();
  radio.setFrequency(freq);
  radio.setBandwidth(bw);
  radio.startReceive();
}

// ═══════════════════════════════════════════════════════════════
// Serial Commands
// ═══════════════════════════════════════════════════════════════

void handleCommand(char cmd) {
  switch (cmd) {
    case 'u':
      scanMode = SCAN_UL_ONLY;
      currentChannel = 0;
      Serial.println("[CMD] Scan mode: UL only");
      break;
    case 'd':
      scanMode = SCAN_DL_ONLY;
      currentChannel = 0;
      Serial.println("[CMD] Scan mode: DL only");
      break;
    case 'a':
      scanMode = SCAN_ALL;
      currentChannel = 0;
      Serial.println("[CMD] Scan mode: ALL channels");
      break;
    case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8':
      scanMode = SCAN_SINGLE;
      currentChannel = cmd - '1';
      singleFreq = UL_CHANNELS[currentChannel];
      singleBW = SUPERLINK_BW_UL;
      radio.standby();
      radio.setFrequency(singleFreq);
      radio.setBandwidth(singleBW);
      radio.startReceive();
      Serial.print("[CMD] Parked on UL CH");
      Serial.print(currentChannel + 1);
      Serial.print(" (");
      Serial.print(singleFreq, 1);
      Serial.println(" MHz)");
      break;
    case 'b':
      scanMode = SCAN_SINGLE;
      singleFreq = BEACON_CHANNEL;
      singleBW = SUPERLINK_BW_DL;
      radio.standby();
      radio.setFrequency(singleFreq);
      radio.setBandwidth(singleBW);
      radio.startReceive();
      Serial.print("[CMD] Parked on Beacon channel (");
      Serial.print(BEACON_CHANNEL, 1);
      Serial.println(" MHz)");
      break;
    case 's':
      printStatus();
      break;
    case '?':
    case 'h':
      printHelp();
      break;
  }
}

// ═══════════════════════════════════════════════════════════════
// Display Helpers
// ═══════════════════════════════════════════════════════════════

String getChannelName() {
  char buf[32];
  switch (scanMode) {
    case SCAN_UL_ONLY:
      snprintf(buf, sizeof(buf), "UL CH%d (%.1f MHz)", currentChannel + 1, UL_CHANNELS[currentChannel]);
      break;
    case SCAN_DL_ONLY:
      snprintf(buf, sizeof(buf), "DL CH%d (%.1f MHz)", currentChannel + 9, DL_CHANNELS[currentChannel]);
      break;
    case SCAN_ALL:
      if (currentChannel < NUM_UL_CHANNELS)
        snprintf(buf, sizeof(buf), "UL CH%d (%.1f MHz)", currentChannel + 1, UL_CHANNELS[currentChannel]);
      else if (currentChannel < NUM_UL_CHANNELS + NUM_DL_CHANNELS)
        snprintf(buf, sizeof(buf), "DL CH%d (%.1f MHz)", currentChannel + 1, DL_CHANNELS[currentChannel - NUM_UL_CHANNELS]);
      else
        snprintf(buf, sizeof(buf), "BCN (%.1f MHz)", BEACON_CHANNEL);
      break;
    case SCAN_SINGLE:
      snprintf(buf, sizeof(buf), "%.1f MHz", singleFreq);
      break;
  }
  return String(buf);
}

void printConfig() {
  Serial.println("╔══════════════════════════════════════╗");
  Serial.println("║ SuperLink Radio Parameters           ║");
  Serial.println("╠══════════════════════════════════════╣");
  Serial.print  ("║ SF:        "); Serial.println(SUPERLINK_SF);
  Serial.print  ("║ BW (UL):   "); Serial.print(SUPERLINK_BW_UL, 0); Serial.println(" kHz");
  Serial.print  ("║ BW (DL):   "); Serial.print(SUPERLINK_BW_DL, 0); Serial.println(" kHz");
  Serial.print  ("║ CR:        4/"); Serial.println(SUPERLINK_CR);
  Serial.print  ("║ Sync Word: 0x"); Serial.println(SUPERLINK_SYNC_WORD, HEX);
  Serial.print  ("║ UL Chans:  "); Serial.print(UL_CHANNELS[0], 1);
  Serial.print("-"); Serial.print(UL_CHANNELS[NUM_UL_CHANNELS-1], 1); Serial.println(" MHz");
  Serial.print  ("║ DL Chans:  "); Serial.print(DL_CHANNELS[0], 1);
  Serial.print("-"); Serial.print(DL_CHANNELS[NUM_DL_CHANNELS-1], 1); Serial.println(" MHz");
  Serial.print  ("║ Beacon:    "); Serial.print(BEACON_CHANNEL, 1); Serial.println(" MHz");
  Serial.print  ("║ Dwell:     "); Serial.print(DWELL_TIME_MS); Serial.println(" ms");
  Serial.println("╚══════════════════════════════════════╝");
}

void printStatus() {
  Serial.println();
  Serial.print("[STATUS] Packets: ");
  Serial.print(totalPackets);
  Serial.print(" | Channel: ");
  Serial.print(getChannelName());
  Serial.print(" | Uptime: ");
  Serial.print(millis() / 1000);
  Serial.println("s");
}

void printHelp() {
  Serial.println();
  Serial.println("Commands:");
  Serial.println("  u     Scan uplink channels only");
  Serial.println("  d     Scan downlink channels only");
  Serial.println("  a     Scan all channels");
  Serial.println("  1-8   Park on UL channel 1-8");
  Serial.println("  b     Park on beacon channel");
  Serial.println("  s     Print status");
  Serial.println("  h/?   This help");
  Serial.println();
}
