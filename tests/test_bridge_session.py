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
