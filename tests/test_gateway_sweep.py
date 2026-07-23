"""Tests for PROPERTY_REQUEST sweep integration in the gateway."""
from superlink.gateway import GatewaySession, State
from superlink.sweep import PropertySweep
from superlink import appmsg
from tests.fixtures.captured_frames import DEFAULT_PAIRING_KEY, SENSOR_MAC


def _active_session_with_sweep(sweep):
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    s = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY,
                       sweep=sweep)
    s.state = State.ACTIVE
    s.session_key = bytes(range(32))
    s.sensor_mac = SENSOR_MAC
    return s


def test_next_probe_body_starts_with_device_info():
    """First probe is DEVICE_INFO_REQUEST — map the surface before fuzzing."""
    s = _active_session_with_sweep(PropertySweep(ids=[43, 44]))
    body = s._next_probe_body()
    assert body[0] == appmsg.MessageId.DEVICE_INFO_REQUEST


def test_next_probe_body_switches_to_property_request_after_device_info():
    sweep = PropertySweep(ids=[43, 44], batch_size=8)
    s = _active_session_with_sweep(sweep)
    s._next_probe_body()                       # consumes the device-info probe
    sweep.set_device_info({"supportedProperties": [], "anonymousDeviceId": b""})
    body = s._next_probe_body()
    assert body[0] == appmsg.MessageId.PROPERTY_REQUEST
    assert list(body[2:]) == [43, 44]          # the batch of ids to probe


def test_next_probe_body_none_when_done():
    sweep = PropertySweep(ids=[43], batch_size=8)
    s = _active_session_with_sweep(sweep)
    s._next_probe_body()                       # device info
    sweep.set_device_info({"supportedProperties": [], "anonymousDeviceId": b""})
    s._next_probe_body()                       # the [43] batch
    assert s._next_probe_body() is None


def test_ingest_device_info_report_populates_sweep_sizes():
    sweep = PropertySweep(ids=[43])
    s = _active_session_with_sweep(sweep)
    report = bytes([
        0x0a, 0x00, 0x00, 0x07, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
        0xa1, 0x12, 0x60, 0x63, 0x02,
    ]) + bytes(range(16)) + bytes([
        0x01, 0x0b,                # supportedMessageIds: [11]
        0x01, 0x01, 0x01, 0x04,    # supportedProperties: UPTIME ch=1 size=4
    ])
    s._ingest_app_report(report)
    assert sweep.sizes == {1: 4}
    assert sweep.anonymous_device_id == bytes(range(16))


def test_ingest_property_report_records_finding():
    """An undefined id (43) returning data must land as a sweep finding."""
    sweep = PropertySweep(ids=[43])
    s = _active_session_with_sweep(sweep)
    s._ingest_app_report(bytes([0x0c, 0x00, 43, 0x00, 0xca, 0xfe]))
    assert len(sweep.findings) == 1
    assert sweep.findings[0]["propertyId"] == 43
    assert sweep.findings[0]["value"] == bytes.fromhex("cafe")


def test_build_0x74_reply_roundtrip():
    """The probe frame must decrypt back to the app-message body."""
    from superlink.decoder import parse_frame, decrypt_frame
    s = _active_session_with_sweep(PropertySweep(ids=[43]))
    body = appmsg.encode_property_request([43], tag=1)
    raw = s._build_0x74_reply(SENSOR_MAC, body)
    f = parse_frame(raw)
    assert f.dctrl == 0x74
    f = decrypt_frame(f, s.session_key, dl_counter=0)   # first reply: counter 0
    assert f.payload == body


def test_0x53_command_window_triggers_probe_tx():
    """Post-adoption, the sensor's 0x53 mgmt poll is its command window. A 0x53
    UL elicits a DL 0x74 probe (seq_hi echoes the 0x53, seq_lo 0x81, ctr 0) that
    decrypts to a DEVICE_INFO_REQUEST. Ground truth: bridge_adopt_fresh_pass2
    frame 62. Probes are NOT fired on 0x54 telemetry (fire-and-forget)."""
    from superlink.decoder import build_frame, parse_frame, decrypt_frame
    s = _active_session_with_sweep(PropertySweep(ids=[43]))
    s._adopted = True  # command window only opens post-commit
    s._ul_counter_offset = 0
    # 0x54 telemetry must NOT elicit a probe now.
    raw54 = build_frame(0xE0, 0x54, SENSOR_MAC, 0x02, 0x00,
                        b"\x00\x00\x00\x00", b"\x0c\x00",
                        s.session_key, counter=2)
    _, tx54, _ = s.handle_rx(raw54, ul_channel=1)
    assert tx54 is None
    # 0x53 command window DOES elicit the DEVICE_INFO_REQUEST probe.
    raw53 = build_frame(0xE0, 0x53, SENSOR_MAC, 0x01, 0x30,
                        b"\x00\x00\x00\x00", b"\x01\x00",
                        s.session_key, counter=0)
    frame, tx_data, tx_freq = s.handle_rx(raw53, ul_channel=1)
    assert tx_data is not None and tx_freq > 0
    tf = parse_frame(tx_data)
    assert tf.dctrl == 0x74 and tf.seq_hi == 0x01 and tf.seq_lo == 0x81
    f = decrypt_frame(tf, s.session_key, dl_counter=0)
    assert f.payload[0] == appmsg.MessageId.DEVICE_INFO_REQUEST


def test_no_sweep_means_no_probe():
    """Sweep off (default) -> gateway never produces a probe body."""
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    s = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    assert s.sweep is None
    assert s._next_probe_body() is None
