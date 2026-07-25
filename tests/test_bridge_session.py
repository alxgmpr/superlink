"""Tests for the extracted DeviceSession (new bridge surface)."""
from superlink.bridge.session import DeviceSession
from superlink.bridge.core import OutgoingFrame
from superlink.bridge.store import DeviceRecord
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.events import Event
from tests.fixtures.captured_frames import (
    SENSOR_MAC, DEFAULT_PAIRING_KEY, FRAME_36B_RAW,
)

GW_MAC = bytes.fromhex("0102030405")  # 5-byte gw mac used by gateway today


def _session():
    return DeviceSession(DeviceRecord(mac=SENSOR_MAC), gw_mac=GW_MAC,
                         pairing_key=DEFAULT_PAIRING_KEY,
                         profiles=ProfileRegistry.load())


def test_feed_returns_frames_and_events_tuple():
    from superlink.decoder import parse_frame
    s = _session()
    frame = parse_frame(FRAME_36B_RAW)   # real parsed SuperLinkFrame
    result = s.feed(frame, channel=1, now=1.0)
    assert isinstance(result, tuple) and len(result) == 2
    frames, events = result
    assert isinstance(frames, list) and isinstance(events, list)


def test_to_record_roundtrips_identity():
    s = _session()
    rec = s.to_record()
    assert rec.mac == SENSOR_MAC


def test_beacon_emitted_on_tick_when_due():
    s = _session()
    s.start(now=0.0)                    # enter BEACONING
    frames, _ = s.tick(now=1000.0)      # well past beacon_interval
    assert any(isinstance(f, OutgoingFrame) for f in frames)


# --- v2 firmware support: discovery-ad recognition + version-aware KDF ctx ---

# Decrypted 0x40 discovery payloads. v1 firmware: 01 ae94 NN 00000000 (8B).
# v2 firmware: 02 ae94 NN 00000000 0002 (10B). The ae94 marker is stable across
# versions; the leading byte is the protocol version.
V1_DISCOVERY_PAYLOAD = bytes.fromhex("01ae940000000000")
V2_DISCOVERY_PAYLOAD = bytes.fromhex("02ae9431000000000002")


def test_is_discovery_ad_accepts_v1_and_v2():
    from superlink.bridge.session import is_discovery_ad
    assert is_discovery_ad(V1_DISCOVERY_PAYLOAD)
    assert is_discovery_ad(V2_DISCOVERY_PAYLOAD)


def test_is_discovery_ad_rejects_non_discovery():
    from superlink.bridge.session import is_discovery_ad
    assert not is_discovery_ad(None)
    assert not is_discovery_ad(b"")
    assert not is_discovery_ad(b"\x01\x02\x03")           # too short
    assert not is_discovery_ad(bytes.fromhex("01dead0000000000"))  # wrong marker
    assert not is_discovery_ad(bytes.fromhex("03ae940000000000"))  # unknown version


def test_initial_pairing_kdf_context_is_version_aware():
    from superlink.bridge.session import (
        initial_pairing_kdf_context, LORA_DEVICE_DEFAULT_ADOPTION_KEY,
    )
    # v1 firmware seeds the session KDF with the pairing key ...
    assert initial_pairing_kdf_context(
        V1_DISCOVERY_PAYLOAD, DEFAULT_PAIRING_KEY) == DEFAULT_PAIRING_KEY
    # ... v2 firmware seeds it with the global default adoption key.
    assert initial_pairing_kdf_context(
        V2_DISCOVERY_PAYLOAD, DEFAULT_PAIRING_KEY) == LORA_DEVICE_DEFAULT_ADOPTION_KEY


def test_default_adoption_key_value():
    from superlink.bridge.session import LORA_DEVICE_DEFAULT_ADOPTION_KEY
    assert LORA_DEVICE_DEFAULT_ADOPTION_KEY == bytes.fromhex(
        "c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db")


def _craft_discovery_frame(payload: bytes):
    """Build a real encrypted 0x40 discovery frame (pairing key, counter 0)."""
    from superlink.decoder import build_frame, compute_mic, parse_frame
    header = bytes([0xE0, 0x40]) + SENSOR_MAC + bytes([0x00, 0x00])
    mic = compute_mic(header, payload)
    raw = build_frame(0xE0, 0x40, SENSOR_MAC, 0x00, 0x00, mic, payload,
                      DEFAULT_PAIRING_KEY, counter=0)
    return parse_frame(raw)


def test_v2_discovery_is_answered_with_connrsp():
    # The old payload[0]==0x01 gate silently dropped v2 discovery (leading 0x02),
    # so the gateway never replied. It must now answer with a ConnRsp.
    s = _session()
    s.start(now=0.0)
    frame = _craft_discovery_frame(V2_DISCOVERY_PAYLOAD)
    frames, _ = s.feed(frame, channel=1, now=1.0)
    assert any(isinstance(f, OutgoingFrame) for f in frames), \
        "v2 discovery should be answered with a ConnRsp"


def test_v2_discovery_selects_adoption_kdf_context():
    from superlink.bridge.session import LORA_DEVICE_DEFAULT_ADOPTION_KEY
    s = _session()
    s.start(now=0.0)
    s.feed(_craft_discovery_frame(V2_DISCOVERY_PAYLOAD), channel=1, now=1.0)
    assert s._kdf_context == LORA_DEVICE_DEFAULT_ADOPTION_KEY


def test_v1_discovery_keeps_pairing_key_kdf_context():
    s = _session()
    s.start(now=0.0)
    s.feed(_craft_discovery_frame(V1_DISCOVERY_PAYLOAD), channel=1, now=1.0)
    assert s._kdf_context == DEFAULT_PAIRING_KEY


def test_explicit_kdf_context_override_is_not_clobbered_by_version():
    # An operator-supplied --kdf-context must survive a v2 discovery.
    override = bytes(range(32))
    s = DeviceSession(DeviceRecord(mac=SENSOR_MAC), gw_mac=GW_MAC,
                      pairing_key=DEFAULT_PAIRING_KEY, kdf_context=override,
                      profiles=ProfileRegistry.load())
    s.start(now=0.0)
    s.feed(_craft_discovery_frame(V2_DISCOVERY_PAYLOAD), channel=1, now=1.0)
    assert s._kdf_context == override
