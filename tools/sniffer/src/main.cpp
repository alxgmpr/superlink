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

#define DWELL_TIME_MS  500   // Fast scan for better capture rate

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
    12,                    // preamble length (SF5/SF6 use 12 per SX1302 HAL)
    1.6,                   // TCXO voltage (Heltec V3 = 1.6V)
    false                  // use LDO
  );

  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("FAILED, code ");
    Serial.println(state);
    while (true) { delay(1000); }
  }
  Serial.println("OK");

  radio.setCRC(true);   // Keep CRC on for proper framing, but accept failures
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
  bool crcOk = (state == RADIOLIB_ERR_NONE);
  if (state != RADIOLIB_ERR_NONE && state != RADIOLIB_ERR_CRC_MISMATCH) {
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
  Serial.print(" t=");
  Serial.print(millis());
  Serial.print("] ");
  Serial.print(getChannelName());
  Serial.print(" | len=");
  Serial.print(len);
  Serial.print(" | RSSI=");
  Serial.print(rssi, 1);
  Serial.print(" | SNR=");
  Serial.print(snr, 1);
  Serial.print(" | CRC=");
  Serial.println(crcOk ? "OK" : "FAIL");

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
      singleFreq = UL_CHANNELS[ch];
      singleBW = SUPERLINK_BW_UL;
      radio.standby();
      radio.setFrequency(singleFreq);
      radio.setBandwidth(singleBW);
      radio.startReceive();
      Serial.printf("[CMD] Parked on UL CH%d (%.1f MHz)\n", ch+1, singleFreq);
      break;
    }
    case '!': case '@': case '#': case '$':
    case '%': case '^': case '&': case '*': {
      // Shift+1-8 for DL channels (!, @, #, $, %, ^, &, *)
      const char shiftMap[] = "!@#$%^&*";
      int ch = -1;
      for (int i = 0; i < 8; i++) { if (cmd == shiftMap[i]) { ch = i; break; } }
      if (ch < 0) break;
      scanMode = SCAN_SINGLE; currentChannel = ch;
      singleFreq = DL_CHANNELS[ch];
      singleBW = SUPERLINK_BW_DL;
      radio.standby();
      radio.setFrequency(singleFreq);
      radio.setBandwidth(singleBW);
      radio.startReceive();
      Serial.printf("[CMD] Parked on DL CH%d (%.1f MHz, 500kHz)\n", ch+9, singleFreq);
      break;
    }
    case 'b':
      scanMode = SCAN_SINGLE;
      singleFreq = BEACON_CHANNEL;
      singleBW = SUPERLINK_BW_DL;
      radio.standby(); radio.setFrequency(singleFreq);
      radio.setBandwidth(singleBW); radio.startReceive();
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
  switch (scanMode) {
    case SCAN_UL_ONLY:
      snprintf(buf, sizeof(buf), "UL CH%d %.1fMHz", currentChannel+1, UL_CHANNELS[currentChannel]);
      break;
    case SCAN_DL_ONLY:
      snprintf(buf, sizeof(buf), "DL CH%d %.1fMHz", currentChannel+9, DL_CHANNELS[currentChannel]);
      break;
    case SCAN_SINGLE:
      snprintf(buf, sizeof(buf), "PARK %.1fMHz", singleFreq);
      break;
    case SCAN_ALL:
      if (currentChannel < NUM_UL_CHANNELS)
        snprintf(buf, sizeof(buf), "UL CH%d %.1fMHz", currentChannel+1, UL_CHANNELS[currentChannel]);
      else if (currentChannel < NUM_UL_CHANNELS + NUM_DL_CHANNELS)
        snprintf(buf, sizeof(buf), "DL CH%d %.1fMHz", currentChannel+1, DL_CHANNELS[currentChannel-NUM_UL_CHANNELS]);
      else
        snprintf(buf, sizeof(buf), "BCN %.1fMHz", BEACON_CHANNEL);
      break;
  }
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
  Serial.println("  a     Scan ALL channels   b     Park on beacon");
  Serial.println("  1-8   Park UL CH 1-8     !@#$%^&*  Park DL CH 9-16");
  Serial.println("  s     Status             (Shift+1-8 for DL channels)");
  Serial.println();
}

// ═══════════════════════════════════════════════════════════════
// OLED Display
// ═══════════════════════════════════════════════════════════════

void updateDisplay() {
  char line[32];
  display.clearBuffer();
  display.setFont(u8g2_font_6x10_tf);

  // Row 1: Mode + channel indicator
  float freq;
  int chNum = 0;
  const char* dir = "";

  switch (scanMode) {
    case SCAN_UL_ONLY:
      freq = UL_CHANNELS[currentChannel];
      chNum = currentChannel + 1;
      dir = "UL";
      snprintf(line, sizeof(line), "SCAN UL  CH%d/8", chNum);
      break;
    case SCAN_DL_ONLY:
      freq = DL_CHANNELS[currentChannel];
      chNum = currentChannel + 9;
      dir = "DL";
      snprintf(line, sizeof(line), "SCAN DL  CH%d/8", currentChannel + 1);
      break;
    case SCAN_ALL: {
      int total = NUM_UL_CHANNELS + NUM_DL_CHANNELS + 1;
      if (currentChannel < NUM_UL_CHANNELS) {
        freq = UL_CHANNELS[currentChannel];
        chNum = currentChannel + 1;
        dir = "UL";
      } else if (currentChannel < NUM_UL_CHANNELS + NUM_DL_CHANNELS) {
        freq = DL_CHANNELS[currentChannel - NUM_UL_CHANNELS];
        chNum = currentChannel + 1;
        dir = "DL";
      } else {
        freq = BEACON_CHANNEL;
        chNum = 17;
        dir = "BCN";
      }
      snprintf(line, sizeof(line), "SCAN ALL %d/%d", currentChannel + 1, total);
      break;
    }
    case SCAN_SINGLE:
      freq = singleFreq;
      if (singleBW < 200) {
        chNum = currentChannel + 1;
        dir = "UL";
      } else if (freq > 927.0) {
        chNum = 17;
        dir = "BCN";
      } else {
        chNum = currentChannel + 9;
        dir = "DL";
      }
      snprintf(line, sizeof(line), "PARK %s CH%d", dir, chNum);
      break;
  }
  display.drawStr(0, 10, line);

  // Row 2: Frequency + radio params
  snprintf(line, sizeof(line), "%.1fMHz %s SF%d %s",
    freq, singleBW < 200 || scanMode != SCAN_SINGLE ? "125k" : "500k",
    SUPERLINK_SF, dir);
  display.drawStr(0, 22, line);

  // Row 3: Packet count + uptime
  unsigned long up = millis() / 1000;
  if (up < 3600) {
    snprintf(line, sizeof(line), "PKT:%-5lu     %lum%02lus", totalPackets, up/60, up%60);
  } else {
    snprintf(line, sizeof(line), "PKT:%-5lu    %luh%02lum", totalPackets, up/3600, (up%3600)/60);
  }
  display.drawStr(0, 34, line);

  // Divider
  display.drawHLine(0, 37, 128);

  if (totalPackets > 0) {
    // Row 4: Last packet info
    snprintf(line, sizeof(line), "RSSI:%.0f SNR:%.1f L:%d", lastRSSI, lastSNR, lastLen);
    display.drawStr(0, 49, line);

    // Row 5: Last MAC + age
    unsigned long age = (millis() - lastPktTime) / 1000;
    char ageBuf[8];
    if (age < 60) snprintf(ageBuf, sizeof(ageBuf), "%lus", age);
    else if (age < 3600) snprintf(ageBuf, sizeof(ageBuf), "%lum", age/60);
    else snprintf(ageBuf, sizeof(ageBuf), "%luh", age/3600);
    snprintf(line, sizeof(line), "%s %s", lastMAC, ageBuf);
    display.drawStr(0, 61, line);
  } else {
    // Scanning animation
    const char* frames[] = {"|", "/", "-", "\\"};
    int frame = (millis() / 250) % 4;
    snprintf(line, sizeof(line), "Listening... %s", frames[frame]);
    display.drawStr(12, 52, line);
  }

  // Channel hop progress bar (bottom pixel row) for scanning modes
  if (scanMode != SCAN_SINGLE) {
    int total = (scanMode == SCAN_UL_ONLY) ? NUM_UL_CHANNELS :
                (scanMode == SCAN_DL_ONLY) ? NUM_DL_CHANNELS :
                NUM_UL_CHANNELS + NUM_DL_CHANNELS + 1;
    int barWidth = (128 * (currentChannel + 1)) / total;
    display.drawBox(0, 63, barWidth, 1);
  }

  display.sendBuffer();
}
