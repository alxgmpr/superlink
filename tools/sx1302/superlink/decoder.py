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
  10      4     MIC (BLAKE2b-32 truncated to 4 bytes)
  14      N     Encrypted payload
"""

from dataclasses import dataclass

try:
    import pysodium
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Known Dctrl values
DCTRL_TABLE = {
    0x54: ("UL", "data"),
    0x44: ("UL", "data-ext"),
    0x63: ("DL", "data"),
    0x74: ("DL", "ack"),
}

# Known payload interpretations
SENSOR_TYPE_REPORT = 0x0C
CMD_DOOR_STATE = 0x0F

MIN_FRAME_LEN = 14  # header(10) + MIC(4)


@dataclass
class SuperLinkFrame:
    """Decoded SuperLink frame."""
    mctrl: int
    dctrl: int
    mac: bytes
    seq_hi: int
    seq_lo: int
    mic: bytes
    direction: str
    frame_type: str
    payload_enc: bytes
    payload: bytes | None = None
    mic_valid: bool | None = None
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
    mic = raw[10:14]
    payload_enc = raw[14:]

    direction, frame_type = DCTRL_TABLE.get(dctrl, ("??", "unknown"))

    return SuperLinkFrame(
        mctrl=mctrl, dctrl=dctrl, mac=mac, seq_hi=seq_hi, seq_lo=seq_lo,
        mic=mic, direction=direction, frame_type=frame_type,
        payload_enc=payload_enc,
    )


def build_nonce(mctrl: int, dctrl: int, mac: bytes, seq_hi: int, seq_lo: int) -> bytes:
    """Build 24-byte XSalsa20 nonce from header fields."""
    nonce = bytes([mctrl, dctrl]) + mac + bytes([seq_hi, seq_lo])
    return nonce.ljust(24, b'\x00')


def decrypt_frame(frame: SuperLinkFrame, key: bytes) -> SuperLinkFrame:
    """Decrypt payload and verify MIC. Mutates and returns the frame."""
    if not HAS_CRYPTO:
        return frame
    if not frame.payload_enc:
        return frame

    nonce = build_nonce(frame.mctrl, frame.dctrl, frame.mac, frame.seq_hi, frame.seq_lo)

    # XSalsa20 stream cipher covers MIC + payload together
    ciphertext = frame.mic + frame.payload_enc
    plaintext = pysodium.crypto_stream_xor(ciphertext, len(ciphertext), nonce, key)

    decrypted_mic = plaintext[:4]
    frame.payload = plaintext[4:]

    # Verify MIC: BLAKE2b over header + decrypted payload
    header = bytes([frame.mctrl, frame.dctrl]) + frame.mac + bytes([frame.seq_hi, frame.seq_lo])
    try:
        computed_mic = pysodium.crypto_generichash(
            header + frame.payload, k=key, outlen=4
        )
        frame.mic_valid = (computed_mic == decrypted_mic)
    except Exception:
        frame.mic_valid = None

    frame.interpretation = interpret_payload(frame.dctrl, frame.payload)
    return frame


def interpret_payload(dctrl: int, payload: bytes) -> str | None:
    """Try to interpret decrypted payload bytes."""
    if not payload or len(payload) < 5:
        return None

    ptype = payload[0]
    cmd = payload[2]

    if ptype == SENSOR_TYPE_REPORT and cmd == CMD_DOOR_STATE:
        state = payload[4] if len(payload) > 4 else None
        if state == 0x00:
            return "DOOR OPEN"
        elif state == 0x01:
            return "DOOR CLOSED"
        else:
            return f"DOOR state=0x{state:02X}" if state is not None else None

    return None
