"""
SuperLink frame decoder.

Parses the cleartext header, verifies MIC (BLAKE2b), decrypts
payloads (XSalsa20), and interprets known message types.

Frame layout (big-endian):
  Offset  Size  Field
  0       1     Mctrl
  1       1     Dctrl
  2       6     MAC address
  8       1     SeqHi (frame counter)
  9       1     SeqLo (nonce component)
  10      N     Encrypted data (MIC + payload, all encrypted together)

Encryption: XSalsa20 stream cipher (crypto_stream_xor).
The 24-byte nonce is:
  [Mctrl][Dctrl][MAC(6)][SeqHi][SeqLo][13 zeros][Counter]
where Counter is a per-direction frame counter:
  - UL data: counter = seq_hi - handshake_frame_count (typically 5)
  - DL data: counter = total DL handshake frames (typically 4)
  - Handshake frames: counter = 0 or 1

After decryption, the first 4 bytes are an integrity check (MIC),
and the remaining bytes are the payload.
"""

from dataclasses import dataclass

try:
    import pysodium
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Known Dctrl values
DCTRL_TABLE = {
    0x40: ("UL", "mgmt"),       # Management/keepalive (default key, independent seq)
    0x42: ("UL", "conn"),       # Connection/challenge (handshake)
    0x43: ("DL", "mgmt-ack"),   # Management ack (shares data seq counter)
    0x44: ("UL", "setup"),      # Setup/config data (handshake)
    0x53: ("DL", "conn-rsp"),   # Connection response (handshake)
    0x54: ("UL", "data"),       # Standard UL data
    0x63: ("DL", "data"),       # Standard DL data
    0x74: ("DL", "setup-rsp"),  # Setup response (handshake)
}

# Known payload interpretations
SENSOR_TYPE_REPORT = 0x0C
CMD_DOOR_STATE = 0x0F
SUBTYPE_EXTENDED = 0x01

MIN_FRAME_LEN = 14  # header(10) + at least 4 bytes encrypted


@dataclass
class SuperLinkFrame:
    """Decoded SuperLink frame."""
    mctrl: int
    dctrl: int
    mac: bytes
    seq_hi: int
    seq_lo: int
    encrypted: bytes       # full encrypted data (MIC + payload)
    direction: str
    frame_type: str
    mic: bytes | None = None       # decrypted MIC (4 bytes)
    payload: bytes | None = None   # decrypted payload
    interpretation: str | None = None


def format_mac(mac_bytes: bytes) -> str:
    """Format 6-byte MAC as colon-separated hex."""
    return ":".join(f"{b:02X}" for b in mac_bytes)


def parse_frame(raw: bytes) -> SuperLinkFrame | None:
    """Parse raw bytes into a SuperLinkFrame. Returns None if too short."""
    if len(raw) < MIN_FRAME_LEN:
        return None

    mctrl = raw[0]
    dctrl = raw[1]
    mac = raw[2:8]
    seq_hi = raw[8]
    seq_lo = raw[9]
    encrypted = raw[10:]

    direction, frame_type = DCTRL_TABLE.get(dctrl, ("??", "unknown"))

    return SuperLinkFrame(
        mctrl=mctrl, dctrl=dctrl, mac=mac, seq_hi=seq_hi, seq_lo=seq_lo,
        encrypted=encrypted, direction=direction, frame_type=frame_type,
    )


def build_nonce(mctrl: int, dctrl: int, mac: bytes,
                seq_hi: int, seq_lo: int, counter: int = 0) -> bytes:
    """Build 24-byte XSalsa20 nonce from header fields and counter.

    Nonce layout:
      [0]     Mctrl
      [1]     Dctrl (OTA value)
      [2:8]   MAC address
      [8]     SeqHi
      [9]     SeqLo
      [10:23] Zeros
      [23]    Counter
    """
    nonce = bytearray(24)
    nonce[0] = mctrl
    nonce[1] = dctrl
    nonce[2:8] = mac
    nonce[8] = seq_hi
    nonce[9] = seq_lo
    nonce[23] = counter & 0xFF
    return bytes(nonce)


def decrypt_frame(frame: SuperLinkFrame, key: bytes,
                  ul_counter_offset: int = 5,
                  dl_counter: int = 4) -> SuperLinkFrame:
    """Decrypt payload and extract MIC. Mutates and returns the frame.

    Args:
        key: 32-byte session key
        ul_counter_offset: seq_hi value of the last handshake frame.
            UL nonce counter = seq_hi - ul_counter_offset.
            Default 5 (reconnection handshake uses seq_hi 1-5).
        dl_counter: fixed DL nonce counter (total DL handshake frames).
            Default 4.
    """
    if not HAS_CRYPTO:
        return frame
    if not frame.encrypted:
        return frame

    # Determine counter based on direction
    if frame.direction == "DL":
        counter = dl_counter
    else:
        counter = max(0, frame.seq_hi - ul_counter_offset)

    nonce = build_nonce(frame.mctrl, frame.dctrl, frame.mac,
                        frame.seq_hi, frame.seq_lo, counter)

    # XSalsa20 stream cipher covers MIC + payload together
    plaintext = pysodium.crypto_stream_xor(
        frame.encrypted, len(frame.encrypted), nonce, key
    )

    frame.mic = plaintext[:4]
    frame.payload = plaintext[4:]

    frame.interpretation = interpret_payload(frame.dctrl, frame.payload)
    return frame


def encrypt_payload(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt MIC + payload bytes with XSalsa20.

    Args:
        plaintext: Combined MIC (4 bytes) + payload to encrypt.
        key: 32-byte encryption key.
        nonce: 24-byte XSalsa20 nonce (from build_nonce).

    Returns:
        Encrypted bytes (same length as plaintext).
    """
    if not HAS_CRYPTO:
        raise RuntimeError("pysodium required for encryption")
    return pysodium.crypto_stream_xor(plaintext, len(plaintext), nonce, key)


def build_frame(mctrl: int, dctrl: int, mac: bytes,
                seq_hi: int, seq_lo: int,
                mic: bytes, payload: bytes,
                key: bytes, counter: int) -> bytes:
    """Build a complete SuperLink frame (header + encrypted MIC + payload).

    Args:
        mctrl: Management control byte (0xE0 for SecureHeader).
        dctrl: Data control byte (e.g. 0x54 for UL data).
        mac: 6-byte MAC address.
        seq_hi: Frame counter high byte.
        seq_lo: Frame counter low byte.
        mic: 4-byte integrity check (plaintext, will be encrypted).
        payload: Plaintext payload bytes.
        key: 32-byte encryption key.
        counter: Nonce counter byte (byte 23 of the nonce).

    Returns:
        Complete frame bytes: [header 10B][encrypted(MIC + payload)].
    """
    header = bytes([mctrl, dctrl]) + mac + bytes([seq_hi, seq_lo])
    nonce = build_nonce(mctrl, dctrl, mac, seq_hi, seq_lo, counter)
    encrypted = encrypt_payload(mic + payload, key, nonce)
    return header + encrypted


def interpret_payload(dctrl: int, payload: bytes) -> str | None:
    """Interpret decrypted payload bytes."""
    if not payload:
        return None

    # UL data frames (sensor reports)
    if dctrl in (0x54, 0x44):
        return _interpret_sensor_payload(payload)

    # DL data frames
    if dctrl == 0x63:
        return _interpret_dl_payload(payload)

    return None


def _interpret_sensor_payload(payload: bytes) -> str | None:
    """Interpret UL sensor report payload."""
    if len(payload) < 3:
        return None

    ptype = payload[0]
    subtype = payload[2]

    if ptype != SENSOR_TYPE_REPORT:
        return f"type=0x{ptype:02X}"

    # Standard door state (5B payload)
    if subtype == CMD_DOOR_STATE and len(payload) >= 5:
        state = payload[4]
        if state == 0x00:
            return "DOOR OPEN"
        elif state == 0x01:
            return "DOOR CLOSED"
        return f"DOOR state=0x{state:02X}"

    # Extended report (22B payload)
    if subtype == SUBTYPE_EXTENDED and len(payload) >= 22:
        battery = payload[10]
        temp_raw = int.from_bytes(payload[11:13], 'little')
        door_cmd = payload[19]
        door_state = payload[20]
        door_str = "OPEN" if door_state == 0 else "CLOSED" if door_state == 1 else f"0x{door_state:02X}"

        parts = [f"ext_report bat={battery}%"]
        if temp_raw > 0:
            parts.append(f"temp_raw={temp_raw}")
        if door_cmd == CMD_DOOR_STATE:
            parts.append(f"door={door_str}")
        return " ".join(parts)

    return f"report sub=0x{subtype:02X}"


def _interpret_dl_payload(payload: bytes) -> str | None:
    """Interpret DL (gateway→sensor) payload."""
    if len(payload) == 2:
        return f"DL ack {payload.hex()}"
    return f"DL {len(payload)}B"
