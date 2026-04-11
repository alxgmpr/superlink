"""
Known-good captured frames, keys, and nonces from OTA captures.
These serve as protocol ground truth for all tests.

Sources:
  - docs/protocol/ota_captures.md (2026-04-04, 2026-04-10)
  - docs/protocol/crypto_keys_captured.md (keyhook captures)
"""

# --- Sensor identity ---
SENSOR_MAC = bytes.fromhex("9041B22E9A53")

# --- Default pairing key (from lorabrd .rodata) ---
DEFAULT_PAIRING_KEY = bytes.fromhex(
    "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
)

# --- Captured OTA frame: 19B standard UL data (door state) ---
# From ota_captures.md first capture session
FRAME_19B_RAW = bytes.fromhex("E054 9041B22E9A53 5B11 9CFFC24C 8A41BC35D6".replace(" ", ""))
# After decryption with session key, counter = 0x5B - 5 = 0x56 = 86:
# MIC = first 4 bytes of decrypted, payload = remaining 5 bytes
# Decrypted payload: 0C 00 0F 00 01 (DOOR CLOSED)

# --- Captured OTA frame: 36B extended UL data ---
# From ota_captures.md second capture session (confirmed decrypted)
FRAME_36B_RAW = bytes.fromhex("E054 9041B22E9A53 0D2D".replace(" ", ""))
# The encrypted portion (26 bytes) follows but we use the full raw from capture
# Key: 3bfc41760a9eb10c01989bfdbfc384f770617d7a5bfa56acc72d90edeefb8c06
# Nonce counter = 0x0D - 5 = 8
# Decrypted: [MIC 4B] 0C 00 01 00 00 08 6E 04 02 00 64 E0 07 03 00 60 0C 16 00 0F 00 00

FRAME_36B_DECRYPTED_PAYLOAD = bytes.fromhex(
    "0C00010000086E04020064E0070300600C1600 0F0000".replace(" ", "")
)

# --- Nonce construction examples ---
# UL data frame: [Mctrl][Dctrl][MAC][SeqHi][SeqLo][13 zeros][Counter]
NONCE_UL_DATA = bytes.fromhex(
    "E054 9041B22E9A53 0D2D 00000000000000000000000000 08".replace(" ", "")
)
# Mctrl=0xE0, Dctrl=0x54, MAC=9041B22E9A53, SeqHi=0x0D, SeqLo=0x2D, Counter=8

# --- DL data frame (16B) ---
FRAME_16B_DL_RAW = bytes.fromhex("E063 9041B22E9A53 4081 DB3C4692D1AD".replace(" ", ""))
# Dctrl=0x63, DL data, 6B encrypted (4B MIC + 2B payload)
# DL counter = 4

# --- Reconnection handshake frames (OTA, 2026-04-10) ---
HANDSHAKE_CONN_63B = {
    "size": 63, "dctrl": 0x42, "seq_hi": 0xDE, "seq_lo": 0x34,
    "description": "Connection/challenge, encrypted with OLD session key, counter=0",
}
HANDSHAKE_RSP_16B = {
    "size": 16, "dctrl": 0x53, "seq_hi": 0x01, "seq_lo": 0x2C,
    "description": "Connection response, 2B payload",
}
HANDSHAKE_SETUP_FRAMES = [
    {"size": 92, "dctrl": 0x44, "seq_hi": 0x02, "seq_lo": 0x81, "payload_len": 78},
    {"size": 41, "dctrl": 0x44, "seq_hi": 0x03, "seq_lo": 0x82, "payload_len": 27},
    {"size": 20, "dctrl": 0x44, "seq_hi": 0x04, "seq_lo": 0x83, "payload_len": 6},
    {"size": 41, "dctrl": 0x44, "seq_hi": 0x05, "seq_lo": 0x84, "payload_len": 27},
]

# --- Challenge nonces (from keyhook) ---
# Challenge request nonce ends with ASCII "UBNU" (55424e55)
CHALLENGE_REQ_NONCE_SUFFIX = bytes.fromhex("55424e55")  # "UBNU"
# Challenge response nonce ends with ASCII "UBNV" (55424e56)
CHALLENGE_RSP_NONCE_SUFFIX = bytes.fromhex("55424e56")  # "UBNV"

# --- Counter rules ---
UL_COUNTER_OFFSET = 5   # UL data counter = seq_hi - 5 (for reconnection)
DL_COUNTER = 4           # DL data counter = 4 (fixed after reconnection handshake)

# --- Channel plan ---
UL_CHANNELS_HZ = [
    915_600_000, 915_800_000, 916_000_000, 916_200_000,
    916_400_000, 916_600_000, 916_800_000, 917_000_000,
]
DL_CHANNELS_HZ = [
    920_400_000, 921_000_000, 921_600_000, 922_200_000,
    922_800_000, 923_400_000, 924_000_000, 924_600_000,
]
BEACON_FREQ_HZ = 927_600_000

# UL channel index (0-7) → paired DL channel freq
UL_TO_DL_FREQ = {i: DL_CHANNELS_HZ[i] for i in range(8)}
