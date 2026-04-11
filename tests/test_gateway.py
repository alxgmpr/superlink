"""Tests for the gateway connection state machine."""
import pytest
from superlink.gateway import GatewaySession, State
from tests.fixtures.captured_frames import (
    DEFAULT_PAIRING_KEY, SENSOR_MAC, DL_CHANNELS_HZ, BEACON_FREQ_HZ,
)


def test_initial_state():
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    assert session.state == State.IDLE
    assert session.gw_mac == gw_mac
    assert session.session_key is None
    assert session.sensor_mac is None


def test_start_transitions_to_beaconing():
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()
    assert session.state == State.BEACONING


def test_beacon_due():
    """Beacon should be due immediately after start."""
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()
    assert session.beacon_due()


def test_build_beacon():
    """Beacon must be a valid plaintext frame with gateway MAC."""
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()
    beacon = session.build_beacon()

    assert isinstance(beacon, bytes)
    assert len(beacon) >= 10
    assert beacon[2:8] == gw_mac


def test_handle_ul_data_in_active_state():
    """In ACTIVE state, received UL data frames should be decrypted."""
    from superlink.decoder import build_frame

    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()

    # Manually advance to ACTIVE state with a known session key
    session.state = State.ACTIVE
    session.session_key = bytes(range(32))
    session.sensor_mac = SENSOR_MAC
    session._ul_counter_offset = 5

    # Build a fake UL data frame
    payload = b"\x0C\x00\x0F\x00\x01"
    mic = b"\xAA\xBB\xCC\xDD"
    raw = build_frame(0xE0, 0x54, SENSOR_MAC, 0x07, 0x2D,
                      mic, payload, session.session_key, counter=2)

    result = session.handle_rx(raw)
    assert result is not None
    assert result.payload == payload
    assert result.mic == mic
    assert result.interpretation == "DOOR CLOSED"


def test_handle_rx_ignores_wrong_mac():
    """In ACTIVE state, frames from unknown MACs should be ignored."""
    from superlink.decoder import build_frame

    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.state = State.ACTIVE
    session.session_key = bytes(range(32))
    session.sensor_mac = SENSOR_MAC
    session._ul_counter_offset = 5

    wrong_mac = bytes.fromhex("112233445566")
    raw = build_frame(0xE0, 0x54, wrong_mac, 0x07, 0x2D,
                      b"\x00" * 4, b"\x00" * 5, session.session_key, counter=2)

    result = session.handle_rx(raw)
    assert result is None
