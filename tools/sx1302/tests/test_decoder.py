"""Tests for SuperLink frame decoder."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from superlink.decoder import parse_frame, build_nonce, format_mac

# Real captured packet from docs/protocol/ota_captures.md
# Standard UL data: E0 54 90 41 B2 2E 9A 53 5B 11 9C FF C2 4C 8A 41 BC 35 D6
SAMPLE_UL = bytes.fromhex("E0549041B22E9A535B119CFFC24C8A41BC35D6")


def test_parse_frame_ul():
    frame = parse_frame(SAMPLE_UL)
    assert frame is not None
    assert frame.mctrl == 0xE0
    assert frame.dctrl == 0x54
    assert frame.mac == bytes.fromhex("9041B22E9A53")
    assert frame.seq_hi == 0x5B
    assert frame.seq_lo == 0x11
    assert frame.mic == bytes.fromhex("9CFFC24C")
    assert frame.payload_enc == bytes.fromhex("8A41BC35D6")
    assert frame.direction == "UL"
    assert frame.frame_type == "data"


def test_parse_frame_too_short():
    assert parse_frame(b"\x00" * 13) is None
    assert parse_frame(b"") is None


def test_parse_frame_no_payload():
    raw = bytes.fromhex("E0549041B22E9A535B119CFFC24C")
    frame = parse_frame(raw)
    assert frame is not None
    assert frame.payload_enc == b""


def test_format_mac():
    assert format_mac(bytes.fromhex("9041B22E9A53")) == "90:41:B2:2E:9A:53"


def test_build_nonce():
    nonce = build_nonce(0xE0, 0x54, bytes.fromhex("9041B22E9A53"), 0x5B, 0x11)
    assert len(nonce) == 24
    assert nonce[:10] == bytes.fromhex("E0549041B22E9A535B11")
    assert nonce[10:] == b"\x00" * 14


def test_parse_frame_dl():
    raw = bytearray(14)
    raw[0] = 0xE0
    raw[1] = 0x63
    frame = parse_frame(bytes(raw))
    assert frame.direction == "DL"
    assert frame.frame_type == "data"


def test_parse_frame_unknown_dctrl():
    raw = bytearray(14)
    raw[1] = 0xFF
    frame = parse_frame(bytes(raw))
    assert frame.direction == "??"
    assert frame.frame_type == "unknown"


if __name__ == "__main__":
    test_parse_frame_ul()
    test_parse_frame_too_short()
    test_parse_frame_no_payload()
    test_format_mac()
    test_build_nonce()
    test_parse_frame_dl()
    test_parse_frame_unknown_dctrl()
    print("All tests passed!")
