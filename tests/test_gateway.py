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

    result, _, _ = session.handle_rx(raw)
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

    result, _, _ = session.handle_rx(raw)
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

    # Both sides hash in the order shared || gateway_pub || sensor_pub
    # (firmware sub_3af5a swaps r6/r8 on the gateway side so both match).
    gw_session_key = derive_session_key(gw_shared, gw_pub, sensor_pub)
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

    result, _, _ = gw.handle_rx(raw)
    assert result is not None
    assert result.payload == payload
    assert result.mic == mic


def test_handle_discovery_in_beaconing():
    """In BEACONING state, 0x40 frames should be decrypted and sensor MAC recorded."""
    from tests.fixtures.captured_frames import DISCOVERY_FRAME_RAW
    from superlink.decoder import build_nonce
    import pysodium

    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()

    result, tx_data, tx_freq = session.handle_rx(DISCOVERY_FRAME_RAW, ul_channel=3)
    assert result is not None
    assert result.payload is not None
    assert result.payload[0] == 0x01  # discovery type
    assert result.payload[1:3] == b"\xAE\x94"  # discovery marker
    assert session.sensor_mac == SENSOR_MAC
    assert session.state == State.BEACONING  # stays in BEACONING
    # Should produce a 0x62 ConnectionRsp on the paired DL channel
    assert tx_data is not None
    assert tx_freq == DL_CHANNELS_HZ[2]  # CH3 → CH11 = 921.6 MHz
    # Verify dctrl=0x62 (DL conn-rsp) and frame is the correct 55-byte size
    assert tx_data[1] == 0x62
    assert len(tx_data) == 10 + 4 + 41  # header + MIC + ConnectionRsp payload
    assert session._pubkey is not None

    # Decrypt the TX frame and verify the layout matches the real gateway:
    #   [0:2]   = 01 01
    #   [2:34]  = 32-byte gateway pubkey
    #   [34:37] = 0a 00 02
    #   [37:41] = 03 fe ff 03
    header = tx_data[:10]
    encrypted = tx_data[10:]
    nonce = build_nonce(0xE0, 0x62, SENSOR_MAC,
                        tx_data[8], tx_data[9], counter=0)
    plaintext = pysodium.crypto_stream_xor(
        encrypted, len(encrypted), nonce, DEFAULT_PAIRING_KEY)
    payload = plaintext[4:]
    assert len(payload) == 41
    assert payload[0:2] == b"\x01\x01"
    assert payload[2:34] == session._pubkey
    assert payload[34:37] == b"\x0a\x00\x02"
    assert payload[37:41] == b"\x03\xfe\xff\x03"


def test_handle_connection_challenge():
    """0x42 ConnectionChallenge should extract pubkey and derive session key."""
    from tests.fixtures.captured_frames import (
        CONN_CHALLENGE_RAW, CONN_CHALLENGE_SENSOR_PUBKEY,
    )

    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()

    result, _, _ = session.handle_rx(CONN_CHALLENGE_RAW)
    assert result is not None
    assert session.sensor_mac == SENSOR_MAC
    assert session._remote_pubkey == CONN_CHALLENGE_SENSOR_PUBKEY
    assert session.session_key is not None
    assert len(session.session_key) == 32
    assert session.state == State.ACTIVE


def test_connection_challenge_derives_correct_key():
    """After ConnectionChallenge, session key should decrypt data from that sensor."""
    from superlink.decoder import build_frame
    from superlink.crypto import (
        generate_keypair, compute_shared_secret, derive_session_key,
    )

    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()

    # Manually craft a ConnectionChallenge with a known sensor keypair.
    # Layout: [13B header] + [32B pubkey] + [4B trailer 03 fe ff 03] = 49B
    sensor_priv, sensor_pub = generate_keypair()

    header_bytes = bytes([0x01, 0x02, 0x01, 0x5D, 0x0B, 0x05,
                          0x68, 0x21, 0x90, 0xF8, 0xB4, 0x06, 0x2B])
    trailer = bytes([0x03, 0xFE, 0xFF, 0x03])
    challenge_payload = header_bytes + sensor_pub + trailer
    assert len(challenge_payload) == 49
    mic = b"\x00" * 4

    raw = build_frame(0xE0, 0x42, SENSOR_MAC, 0x10, 0x55,
                      mic, challenge_payload, DEFAULT_PAIRING_KEY, counter=0)

    session.handle_rx(raw, ul_channel=3)
    assert session.state == State.ACTIVE
    assert session.session_key is not None

    # Sensor derives: blake2b(shared || gw_pub || sensor_pub || pairing_key)
    # The pairing_key context comes from keypair+0x30, populated by the JSON
    # "add device" handler (sub_5be1c → sub_54020 arg4). For factory pairing
    # the "key" field == default pairing key.
    sensor_shared = compute_shared_secret(sensor_priv, session._pubkey)
    sensor_key = derive_session_key(
        sensor_shared, session._pubkey, sensor_pub,
        context=DEFAULT_PAIRING_KEY,
    )

    assert session.session_key == sensor_key

    # Verify: a frame encrypted by the sensor decrypts correctly
    data_payload = b"\x0C\x00\x0F\x00\x01"
    data_mic = b"\xDE\xAD\xBE\xEF"
    seq_hi = session._ul_counter_offset + 1
    data_raw = build_frame(0xE0, 0x54, SENSOR_MAC, seq_hi, 0x99,
                           data_mic, data_payload, sensor_key, counter=1)

    result, _, _ = session.handle_rx(data_raw)
    assert result is not None
    assert result.payload == data_payload
