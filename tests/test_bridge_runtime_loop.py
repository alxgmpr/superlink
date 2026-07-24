from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.runtime import BridgeRuntime
from superlink.bridge.core import OutgoingFrame
from superlink.bridge.store import InMemoryDeviceStore
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.session import DeviceSession
from tests.support.fake_hal import FakeHal, make_packet
from tests.fixtures.captured_frames import (
    DISCOVERY_FRAME_RAW, CONN_CHALLENGE_RAW, SENSOR_MAC,
)

GW = bytes.fromhex("010203040506")


def _cfg(adopt=ADOPT_ALL, delay=1_000_000, spacing=500_000):
    return RuntimeConfig(gw_mac=GW, pairing_key=DEFAULT_PAIRING_KEY, adopt=adopt,
                         downlink_delay_us=delay, burst_spacing_us=spacing)


def test_schedule_timestamps_and_burst_spacing():
    rt = BridgeRuntime(_cfg(), FakeHal(), store=InMemoryDeviceStore())
    frames = [OutgoingFrame(data=b"\xe0\x62aaa", freq_hz=920_400_000, channel=1),
              OutgoingFrame(data=b"\xe0\x63bbb", freq_hz=920_400_000, channel=1)]
    rt._schedule(frames, base_ts=1000)
    sent = rt.hal.sent
    assert len(sent) == 2
    assert sent[0]["tx_timestamp_us"] == 1000 + 1_000_000
    assert sent[1]["tx_timestamp_us"] == 1000 + 1_000_000 + 500_000


def test_schedule_tx_error_does_not_kill_loop():
    hal = FakeHal(fail_on_send_index=0)
    rt = BridgeRuntime(_cfg(), hal, store=InMemoryDeviceStore())
    frames = [OutgoingFrame(data=b"x", freq_hz=1, channel=1),
              OutgoingFrame(data=b"y", freq_hz=2, channel=1)]
    rt._schedule(frames, base_ts=0)          # first send raises, must be swallowed
    assert len(hal.sent) == 1 and hal.sent[0]["payload"] == b"y"


def test_poll_once_ignores_bad_crc():
    rt = BridgeRuntime(_cfg(), FakeHal(inbox=[make_packet(b"\x00" * 20, crc_ok=False)]),
                       store=InMemoryDeviceStore())
    rt.poll_once(now=1.0)
    assert rt.hal.sent == []


def test_poll_once_drives_real_session_to_emit_0x62():
    """End-to-end: an allowlisted sensor's 0x40 then 0x42 through poll_once must
    result in a scheduled 0x62 send at rx_ts + downlink_delay_us."""
    def factory(record):
        return DeviceSession(record, gw_mac=GW, pairing_key=DEFAULT_PAIRING_KEY,
                             profiles=ProfileRegistry.load())
    hal = FakeHal(inbox=[make_packet(DISCOVERY_FRAME_RAW, ul_channel=1, timestamp_us=5000)])
    rt = BridgeRuntime(_cfg(adopt=ADOPT_ALL), hal, store=InMemoryDeviceStore())
    rt.poll_once(now=1.0)                     # discover + auto-adopt + first response
    # feed the ConnectionChallenge next
    hal.inbox = [make_packet(CONN_CHALLENGE_RAW, ul_channel=1, timestamp_us=9000)]
    rt.poll_once(now=2.0)
    assert any(s["payload"][1] == 0x62 for s in hal.sent), "no 0x62 scheduled"
    chal = [s for s in hal.sent if s["payload"][1] == 0x62][-1]
    assert chal["tx_timestamp_us"] == 9000 + 1_000_000
