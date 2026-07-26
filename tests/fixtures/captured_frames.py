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

# --- Initial pairing capture (2026-04-12) ---
# Sensor factory-reset, adopted by Ubiquiti gateway while sniffing

# Discovery advertisement (0x40, default pairing key, counter=0)
# Payload decrypts to: 01 AE 94 XX 00 00 00 00 (XX = incrementing counter)
DISCOVERY_FRAME_RAW = bytes.fromhex("e0409041b22e9a53ab0685767ec4d241c152ee06610b")
DISCOVERY_PAYLOAD = bytes.fromhex("01ae940000000000")

# ConnectionChallenge (0x42, default pairing key, counter=0, 49B payload)
# Contains sensor's Curve25519 pubkey at payload offset 17
CONN_CHALLENGE_RAW = bytes.fromhex(
    "e0429041b22e9a53ae3cd84dfd259f95149565be52376074770e70475d04b6aa"
    "357ed40ef4f847618cfe4665fb1c8c08c55d4a2adb57cbb5c572c0e492f447"
)
CONN_CHALLENGE_PAYLOAD = bytes.fromhex(
    "0102015d0b05682190f8b4062b47c72fa57f36ecc60aaccccd6776be392d8f6b"
    "d509797cc1c1bacfbca4df836f03feff03"
)
# 0x42 plaintext layout (49 bytes) — settled 2026-07-24 against real-bridge
# ground truth in captures/live/bridge_pair_keyhook_20260722.log, where the
# bridge's own scalarmult call takes PUB = payload[3:35] verbatim:
#   [0:3]   = 01 02 01        outer stamp (01 02) + type byte (01)
#   [3:35]  = 32-byte sensor pubkey  (fed directly into DH scalarmult)
#   [35:45] = 10B inner blob  (session_key + zero nonce) -> sensor_mac(6B) || u32(4B)
#   [45:49] = 03 fe ff 03     fixed ChMap trailer (matches 0x62 trailer)
# Superseded guesses: [17:49] (swallowed trailer) and [13:45] (both were
# passive-sniff guesses with no DH to validate the offset). See memory
# connchallenge_offset_open and CONN_CHALLENGE_GROUND_TRUTH below.
CONN_CHALLENGE_SENSOR_PUBKEY = CONN_CHALLENGE_PAYLOAD[3:35]
CONN_CHALLENGE_INNER_BLOB = CONN_CHALLENGE_PAYLOAD[35:45]
CONN_CHALLENGE_TRAILER = bytes.fromhex("03feff03")

# --- Real-bridge ConnectionChallenge ground truth (keyhook, 2026-07-22) ---
# From captures/live/bridge_pair_keyhook_20260722.log: an operational reconnect
# of sensor 9041b22e9a53. Every value below is logged verbatim by the LD_PRELOAD
# keyhook on the real Ubiquiti bridge, so this is DH-validated (not a sniff
# guess) and pins the [3:35] pubkey offset decisively.
CONN_CHALLENGE_GROUND_TRUTH = {
    # 0x42 frame as it left the air: header || outer-encrypted body (MIC+PT).
    "raw": bytes.fromhex(
        "e0429041b22e9a53b319"
        "d26c7bcc03e3398df8e2c82a02ecc24035a2720fe51451faf599dfc42ad1d29a"
        "6d0ceac2e3049f22b23e819acb76f959049b80f7ca"
    ),
    # Outer XSalsa20 transport key (fallbackKey for this reconnect).
    "transport_key": bytes.fromhex(
        "fd0a631ff4656a9eb8cd5893766e2398012c3edee9305cddf594455acd320d6d"),
    # Gateway (bridge) DH keypair used for this handshake.
    "gw_priv": bytes.fromhex(
        "6b7e266b72f1faf97f731fe346a6aab72541503b60d0cf67c404601aedc46fb7"),
    "gw_pub": bytes.fromhex(
        "5d1a395b0489244a6a5e11033ed2fd73a2337a3364648899101ea1b6530b0b58"),
    # Session-KDF context = the rotated addDevice.key for this adopted sensor.
    "kdf_context": bytes.fromhex(
        "236f0651e06043c70d7c3ec468660c5628569b28ba59d1cca74e01d8adc46968"),
    # Expected outputs.
    "sensor_pubkey": bytes.fromhex(
        "14b93c2ce18a94c74c6197327c5c9e0bef57bcc117bf684e2737eac5e93da006"),
    "session_key": bytes.fromhex(
        "9432ba8ee9114dedc8370233f9a6fbc1cb66a33e4ccb9669cfe41601df6d3336"),
    "inner_sensor_mac": bytes.fromhex("9041b22e9a53"),
    "inner_u32": bytes.fromhex("61ca8b5e"),
}

# Gateway DL ACK captured (0x63, 16B, session key)
PAIRING_DL_ACK_RAW = bytes.fromhex("e0639041b22e9a5302828a24b9bc4c9d")

# Gateway DL setup response (0x74, 19B, session key)
PAIRING_DL_SETUP_RSP_RAW = bytes.fromhex("e0749041b22e9a530401aea9bfd9bf70c98310")

# Connection message types (from Ghidra binary analysis of FUN_000524ac)
CONN_MSG_TYPE_REQ = 0       # ConnectionReq (case 0)
CONN_MSG_TYPE_CHALLENGE = 2  # ConnectionChallenge (case 2)

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
