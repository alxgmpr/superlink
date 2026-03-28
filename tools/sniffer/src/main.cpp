/*
 * SuperLink LoRa Sniffer for Heltec LoRa 32 V3 (SX1262)
 *
 * Configures the radio for SuperLink parameters (SF5, 125kHz, private sync word)
 * and dumps any received packets to serial. Cycles through all 8 uplink channels
 * and the beacon channel.
 *
 * Hardware: Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262)
 * Library:  RadioLib (https://github.com/jgromes/RadioLib)
 */

#include <Arduino.h>
#include <RadioLib.h>
#include <SPI.h>
#include <Wire.h>
#include <U8g2lib.h>

// Forward declarations
void handlePacket();
void hopChannel();
void handleCommand(char cmd);
String getChannelName();
void printConfig();
void printStatus();
void printHelp();
void updateDisplay();

// Heltec V3 OLED: SSD1306 128x64, I2C on SDA=17, SCL=18, RST=21
U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(U8G2_R0, 21, 18, 17);

// Heltec V3 SX1262 pins (from pins_arduino.h)
SX1262 radio = new Module(8, 14, 12, 13);  // SS, DIO1, RST, BUSY

// ═══════════════════════════════════════════════════════════════
// SuperLink Protocol Parameters (from firmware RE)
// ═══════════════════════════════════════════════════════════════

#define SUPERLINK_SYNC_WORD  0x12   // Standard private LoRa (register 0x1424)
#define SUPERLINK_SF         5      // Spreading Factor 5 (Semtech extension)
#define SUPERLINK_BW_UL      125.0  // Uplink bandwidth kHz
#define SUPERLINK_BW_DL      500.0  // Downlink bandwidth kHz
#define SUPERLINK_CR         5      // Coding rate 4/5

// Uplink channels (125 kHz, SF5) - sensor -> gateway
const float UL_CHANNELS[] = {
  915.6, 915.8, 916.0, 916.2, 916.4, 916.6, 916.8, 917.0
};
#define NUM_UL_CHANNELS 8

// Downlink channels (500 kHz, SF5) - gateway -> sensor
const float DL_CHANNELS[] = {
  920.4, 921.0, 921.6, 922.2, 922.8, 923.4, 924.0, 924.6
};
#define NUM_DL_CHANNELS 8

#define BEACON_CHANNEL  927.6

// ═══════════════════════════════════════════════════════════════
// Sniffer Configuration
// ═══════════════════════════════════════════════════════════════

#define DWELL_TIME_MS  2000

enum ScanMode { SCAN_UL_ONLY, SCAN_DL_ONLY, SCAN_ALL, SCAN_SINGLE };
ScanMode scanMode = SCAN_UL_ONLY;
float singleFreq = 916.0;
float singleBW = 125.0;

// ═══════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════

volatile bool rxFlag = false;
int currentChannel = 0;
unsigned long lastHopTime = 0;
unsigned long lastDisplayTime = 0;
unsigned long totalPackets = 0;

// Last packet info for display
float lastRSSI = 0;
float lastSNR = 0;
int lastLen = 0;
char lastMAC[18] = "---";
uint8_t lastMctrl = 0;
unsigned long lastPktTime = 0;

void setRxFlag(void) { rxFlag = true; }

// ═══════════════════════════════════════════════════════════════
// Setup
// ═══════════════════════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println();
  Serial.println("========================================");
  Serial.println("  OpenSuperLink LoRa Sniffer v0.1");
  Serial.println("  Heltec LoRa 32 V3 (SX1262)");
  Serial.println("========================================");
  Serial.println();

  // Heltec V3: enable Vext power (powers both OLED and LoRa)
  pinMode(36, OUTPUT);
  digitalWrite(36, LOW);
  delay(100);

  // Init OLED display
  display.begin();
  display.setFont(u8g2_font_6x10_tf);
  display.clearBuffer();
  display.drawStr(16, 28, "OpenSuperLink");
  display.drawStr(24, 42, "Sniffer v0.1");
  display.sendBuffer();
  delay(500);

  // Reset LoRa module
  pinMode(12, OUTPUT);
  digitalWrite(12, LOW);
  delay(10);
  digitalWrite(12, HIGH);
  delay(100);

  // Init SPI
  SPI.begin(9, 11, 10, 8);

  // Initialize SX1262 with SuperLink parameters
  // IMPORTANT: Heltec V3 needs TCXO voltage = 1.6V
  Serial.print("[SX1262] Initializing... ");
  int state = radio.begin(
    UL_CHANNELS[0],       // frequency (MHz)
    SUPERLINK_BW_UL,      // bandwidth (kHz)
    SUPERLINK_SF,          // spreading factor
    SUPERLINK_CR,          // coding rate 4/x
    SUPERLINK_SYNC_WORD,   // sync word
    10,                    // output power dBm
    8,                     // preamble length
    1.6,                   // TCXO voltage (Heltec V3 = 1.6V)
    false                  // use LDO
  );

  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("FAILED, code ");
    Serial.println(state);
    while (true) { delay(1000); }
  }
  Serial.println("OK");

  radio.setCRC(true);
  radio.setDio1Action(setRxFlag);

  printConfig();

  Serial.println("[RX] Starting continuous receive...");
  Serial.println("     Send 'h' for help");
  Serial.println();

  state = radio.startReceive();
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("[RX] startReceive failed: ");
    Serial.println(state);
  }

  lastHopTime = millis();
}

// ═══════════════════════════════════════════════════════════════
// Main Loop
// ═══════════════════════════════════════════════════════════════

void loop() {
  if (rxFlag) {
    rxFlag = false;
    handlePacket();
  }

  if (scanMode != SCAN_SINGLE && (millis() - lastHopTime > DWELL_TIME_MS)) {
    hopChannel();
    lastHopTime = millis();
  }

  if (Serial.available()) {
    handleCommand(Serial.read());
  }

  // Update display every 250ms
  if (millis() - lastDisplayTime > 250) {
    updateDisplay();
    lastDisplayTime = millis();
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
  lastRSSI = rssi;
  lastSNR = snr;
  lastLen = len;
  lastPktTime = millis();

  // Save MAC for display
  if (len >= 8) {
    snprintf(lastMAC, sizeof(lastMAC), "%02X:%02X:%02X:%02X:%02X:%02X",
      buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
    lastMctrl = buf[0];
  }

  Serial.print("[PKT #");
  Serial.print(totalPackets);
  Serial.print("] ");
  Serial.print(getChannelName());
  Serial.print(" | len=");
  Serial.print(len);
  Serial.print(" | RSSI=");
  Serial.print(rssi, 1);
  Serial.print(" | SNR=");
  Serial.println(snr, 1);

  // Hex dump
  Serial.print("  HEX: ");
  for (int i = 0; i < len; i++) {
    if (buf[i] < 0x10) Serial.print("0");
    Serial.print(buf[i], HEX);
    if (i < len - 1) Serial.print(" ");
  }
  Serial.println();

  // Parse SuperLink header if long enough (14+ bytes)
  if (len >= 14) {
    uint8_t mctrl = buf[0];
    uint8_t dctrl = buf[1];
    uint16_t seq = (buf[8] << 8) | buf[9];

    Serial.print("  HDR: mctrl=0x");
    if (mctrl < 0x10) Serial.print("0");
    Serial.print(mctrl, HEX);
    Serial.print(" dctrl=0x");
    if (dctrl < 0x10) Serial.print("0");
    Serial.print(dctrl, HEX);
    Serial.print(" mac=");
    for (int i = 2; i < 8; i++) {
      if (buf[i] < 0x10) Serial.print("0");
      Serial.print(buf[i], HEX);
      if (i < 7) Serial.print(":");
    }
    Serial.print(" seq=0x");
    Serial.print(seq, HEX);
    Serial.print(" mic=");
    for (int i = 10; i < 14; i++) {
      if (buf[i] < 0x10) Serial.print("0");
      Serial.print(buf[i], HEX);
    }
    Serial.println();

    if (len > 14) {
      Serial.print("  PAY: ");
      for (int i = 14; i < len && i < 64; i++) {
        if (buf[i] < 0x10) Serial.print("0");
        Serial.print(buf[i], HEX);
        Serial.print(" ");
      }
      if (len > 64) Serial.print("...");
      Serial.println();
    }
  }
  Serial.println();
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
      int total = NUM_UL_CHANNELS + NUM_DL_CHANNELS + 1;
      currentChannel = (currentChannel + 1) % total;
      if (currentChannel < NUM_UL_CHANNELS) {
        freq = UL_CHANNELS[currentChannel]; bw = SUPERLINK_BW_UL;
      } else if (currentChannel < NUM_UL_CHANNELS + NUM_DL_CHANNELS) {
        freq = DL_CHANNELS[currentChannel - NUM_UL_CHANNELS]; bw = SUPERLINK_BW_DL;
      } else {
        freq = BEACON_CHANNEL; bw = SUPERLINK_BW_DL;
      }
      break;
    }
    default: return;
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
    case 'u': scanMode = SCAN_UL_ONLY; currentChannel = 0;
      Serial.println("[CMD] Scan: UL only"); break;
    case 'd': scanMode = SCAN_DL_ONLY; currentChannel = 0;
      Serial.println("[CMD] Scan: DL only"); break;
    case 'a': scanMode = SCAN_ALL; currentChannel = 0;
      Serial.println("[CMD] Scan: ALL"); break;
    case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': {
      int ch = cmd - '1';
      scanMode = SCAN_SINGLE; currentChannel = ch;
      radio.standby();
      radio.setFrequency(UL_CHANNELS[ch]);
      radio.setBandwidth(SUPERLINK_BW_UL);
      radio.startReceive();
      Serial.printf("[CMD] Parked on UL CH%d (%.1f MHz)\n", ch+1, UL_CHANNELS[ch]);
      break;
    }
    case 'b':
      scanMode = SCAN_SINGLE;
      radio.standby(); radio.setFrequency(BEACON_CHANNEL);
      radio.setBandwidth(SUPERLINK_BW_DL); radio.startReceive();
      Serial.printf("[CMD] Parked on Beacon (%.1f MHz)\n", BEACON_CHANNEL);
      break;
    case 's': printStatus(); break;
    case 'h': case '?': printHelp(); break;
  }
}

// ═══════════════════════════════════════════════════════════════
// Display
// ═══════════════════════════════════════════════════════════════

String getChannelName() {
  char buf[32];
  if (scanMode == SCAN_UL_ONLY)
    snprintf(buf, sizeof(buf), "UL%d %.1fMHz", currentChannel+1, UL_CHANNELS[currentChannel]);
  else if (scanMode == SCAN_DL_ONLY)
    snprintf(buf, sizeof(buf), "DL%d %.1fMHz", currentChannel+9, DL_CHANNELS[currentChannel]);
  else if (scanMode == SCAN_SINGLE)
    snprintf(buf, sizeof(buf), "%.1fMHz", singleFreq);
  else
    snprintf(buf, sizeof(buf), "CH%d", currentChannel+1);
  return String(buf);
}

void printConfig() {
  Serial.println("  Radio Config:");
  Serial.printf("    SF=%d  BW_UL=%.0fkHz  BW_DL=%.0fkHz  CR=4/%d\n",
    SUPERLINK_SF, SUPERLINK_BW_UL, SUPERLINK_BW_DL, SUPERLINK_CR);
  Serial.printf("    SyncWord=0x%02X  Preamble=8  CRC=on\n", SUPERLINK_SYNC_WORD);
  Serial.printf("    UL: %.1f-%.1f MHz  DL: %.1f-%.1f MHz  BCN: %.1f MHz\n",
    UL_CHANNELS[0], UL_CHANNELS[NUM_UL_CHANNELS-1],
    DL_CHANNELS[0], DL_CHANNELS[NUM_DL_CHANNELS-1], BEACON_CHANNEL);
  Serial.printf("    Dwell: %dms\n", DWELL_TIME_MS);
  Serial.println();
}

void printStatus() {
  Serial.printf("\n[STATUS] Packets=%lu  Chan=%s  Uptime=%lus\n",
    totalPackets, getChannelName().c_str(), millis()/1000);
}

void printHelp() {
  Serial.println("\nCommands:");
  Serial.println("  u     Scan UL channels   d     Scan DL channels");
  Serial.println("  a     Scan ALL channels   1-8   Park on UL CH 1-8");
  Serial.println("  b     Park on beacon      s     Status");
  Serial.println();
}

// ═══════════════════════════════════════════════════════════════
// OLED Display
// ═══════════════════════════════════════════════════════════════

void updateDisplay() {
  char line[32];
  display.clearBuffer();

  // Row 1: Title
  display.setFont(u8g2_font_6x10_tf);
  display.drawStr(0, 10, "SuperLink Sniffer");

  // Row 2: Current channel + scan mode
  float freq;
  const char* mode;
  if (scanMode == SCAN_UL_ONLY) {
    freq = UL_CHANNELS[currentChannel];
    mode = "UL";
  } else if (scanMode == SCAN_DL_ONLY) {
    freq = DL_CHANNELS[currentChannel];
    mode = "DL";
  } else if (scanMode == SCAN_SINGLE) {
    freq = singleFreq;
    mode = "PARK";
  } else {
    freq = currentChannel < NUM_UL_CHANNELS ? UL_CHANNELS[currentChannel] :
           currentChannel < NUM_UL_CHANNELS + NUM_DL_CHANNELS ?
           DL_CHANNELS[currentChannel - NUM_UL_CHANNELS] : BEACON_CHANNEL;
    mode = "ALL";
  }
  snprintf(line, sizeof(line), "%s %.1fMHz SF%d", mode, freq, SUPERLINK_SF);
  display.drawStr(0, 22, line);

  // Row 3: Packet count + uptime
  snprintf(line, sizeof(line), "PKT:%-5lu  %lus", totalPackets, millis()/1000);
  display.drawStr(0, 34, line);

  // Divider
  display.drawHLine(0, 37, 128);

  if (totalPackets > 0) {
    // Row 4: Last packet RSSI/SNR
    snprintf(line, sizeof(line), "RSSI:%.0f SNR:%.1f L:%d", lastRSSI, lastSNR, lastLen);
    display.drawStr(0, 49, line);

    // Row 5: Last MAC
    snprintf(line, sizeof(line), "%s", lastMAC);
    display.drawStr(0, 61, line);

    // Age indicator
    unsigned long age = (millis() - lastPktTime) / 1000;
    if (age < 60) {
      snprintf(line, sizeof(line), "%lus", age);
    } else {
      snprintf(line, sizeof(line), "%lum", age / 60);
    }
    display.drawStr(110, 61, line);
  } else {
    // No packets yet
    display.drawStr(12, 52, "Listening...");

    // Scanning animation
    int dot = (millis() / 500) % 4;
    for (int i = 0; i < dot; i++) {
      display.drawStr(84 + i*6, 52, ".");
    }
  }

  display.sendBuffer();
}
