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


def test_parse_args_required_mac():
    """--mac is required."""
    from superlink.gateway import parse_gw_args
    with pytest.raises(SystemExit):
        parse_gw_args([])


def test_parse_args_defaults():
    """Defaults should be sensible."""
    from superlink.gateway import parse_gw_args
    args = parse_gw_args(["--mac", "AA:BB:CC:DD:EE:FF"])
    assert args.mac == "AA:BB:CC:DD:EE:FF"
    assert args.beacon_interval == 240
    assert args.log is None
    assert args.verbose is False


def test_dh_full_exchange():
    """Simulate sensor + gateway DH exchange, verify shared session key."""
    from superlink.crypto import (
        generate_keypair, compute_shared_secret, derive_session_key,
    )

    # Gateway generates keypair
    gw_priv, gw_pub = generate_keypair()

    # Sensor generates keypair
    sensor_priv, sensor_pub = generate_keypair()

    # Both compute shared secret
    gw_shared = compute_shared_secret(gw_priv, sensor_pub)
    sensor_shared = compute_shared_secret(sensor_priv, gw_pub)
    assert gw_shared == sensor_shared

    # Gateway derives session key (is_initiator=False: first=local, second=remote)
    gw_session_key = derive_session_key(gw_shared, gw_pub, sensor_pub)

    # Sensor derives session key (is_initiator=True: first=remote, second=local)
    sensor_session_key = derive_session_key(sensor_shared, gw_pub, sensor_pub)

    # Both must derive the same key
    assert gw_session_key == sensor_session_key
    assert len(gw_session_key) == 32


def test_sensor_frame_decrypted_by_gateway():
    """A frame encrypted with the session key should be decryptable by the gateway."""
    from superlink.crypto import (
        generate_keypair, compute_shared_secret, derive_session_key,
    )
    from superlink.decoder import build_frame

    # Establish session
    gw_priv, gw_pub = generate_keypair()
    sensor_priv, sensor_pub = generate_keypair()
    shared = compute_shared_secret(gw_priv, sensor_pub)
    session_key = derive_session_key(shared, gw_pub, sensor_pub)

    # Sensor builds a UL data frame
    sensor_mac = SENSOR_MAC
    payload = b"\x0C\x00\x0F\x00\x01"  # door closed
    mic = b"\x11\x22\x33\x44"
    seq_hi = 0x06
    counter_offset = 5
    counter = seq_hi - counter_offset  # = 1

    raw = build_frame(0xE0, 0x54, sensor_mac, seq_hi, 0x99,
                      mic, payload, session_key, counter)

    # Gateway receives and decrypts
    gw = GatewaySession(gw_mac=bytes(6), pairing_key=DEFAULT_PAIRING_KEY)
    gw.state = State.ACTIVE
    gw.session_key = session_key
    gw.sensor_mac = sensor_mac
    gw._ul_counter_offset = counter_offset

    result = gw.handle_rx(raw)
    assert result is not None
    assert result.payload == payload
    assert result.mic == mic
