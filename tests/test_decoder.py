"""Tests for SuperLink frame encoding and decoding."""
import pytest
from superlink.decoder import (
    build_nonce, decrypt_frame, encrypt_payload, parse_frame,
)
from tests.fixtures.captured_frames import SENSOR_MAC, NONCE_UL_DATA


def test_encrypt_decrypt_roundtrip():
    """XSalsa20 encrypt then decrypt should recover the original."""
    key = bytes(range(32))
    nonce = build_nonce(0xE0, 0x54, SENSOR_MAC, 0x07, 0x2D, counter=2)
    plaintext = b"\x0C\x00\x0F\x00\x01"
    mic = b"\xAA\xBB\xCC\xDD"

    encrypted = encrypt_payload(mic + plaintext, key, nonce)
    assert len(encrypted) == len(mic) + len(plaintext)
    assert encrypted != mic + plaintext

    import pysodium
    decrypted = pysodium.crypto_stream_xor(encrypted, len(encrypted), nonce, key)
    assert decrypted[:4] == mic
    assert decrypted[4:] == plaintext


def test_build_frame_roundtrip():
    """build_frame output should be parseable by parse_frame."""
    from superlink.decoder import build_frame

    key = bytes(range(32))
    mac = SENSOR_MAC
    payload = b"\x0C\x00\x0F\x00\x01"
    mic = b"\x11\x22\x33\x44"

    raw = build_frame(
        mctrl=0xE0, dctrl=0x54, mac=mac,
        seq_hi=0x07, seq_lo=0x2D,
        mic=mic, payload=payload,
        key=key, counter=2,
    )

    assert len(raw) == 19

    frame = parse_frame(raw)
    assert frame is not None
    assert frame.mctrl == 0xE0
    assert frame.dctrl == 0x54
    assert frame.mac == mac
    assert frame.seq_hi == 0x07
    assert frame.seq_lo == 0x2D
    assert len(frame.encrypted) == 9

    frame = decrypt_frame(frame, key, ul_counter_offset=5)
    assert frame.mic == mic
    assert frame.payload == payload


def test_nonce_matches_capture():
    """Nonce construction must match keyhook-captured nonces."""
    nonce = build_nonce(0xE0, 0x54, SENSOR_MAC, 0x0D, 0x2D, counter=8)
    assert nonce == NONCE_UL_DATA
    assert len(nonce) == 24
    assert nonce[23] == 8


def test_nonce_counter_zero_padding():
    """Bytes 10-22 must be zero."""
    nonce = build_nonce(0xE0, 0x54, SENSOR_MAC, 0x07, 0x2D, counter=2)
    assert nonce[10:23] == b"\x00" * 13
