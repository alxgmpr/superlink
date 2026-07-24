"""
End-to-end integration test: raw captured frames -> BridgeCore -> DeviceSession
-> events, using the real (non-mock) DeviceSession as the session_factory.

This wires Task 7's DeviceSession into Task 6's BridgeCore and drives it with
real captured wire bytes from tests/fixtures/captured_frames.py.

Realistic-assertion note (see task-8-report.md for detail): a freshly
discovered/auto-adopted device has no session key yet (that only happens after
the DH handshake completes over several more frames), so we assert on
discovery and per-MAC session routing rather than decrypted property values.

Fixture note (see task-8-report.md): the brief's test uses FRAME_36B_RAW, but
that fixture constant is only the 10-byte cleartext header (no encrypted
payload bytes) -- below decoder.MIN_FRAME_LEN (14), so superlink.decoder.
parse_frame() returns None for it and no frame ever reaches BridgeCore's
routing logic at all (feed() short-circuits on `frame is None`). We use
DISCOVERY_FRAME_RAW instead: a real captured 0x40 discovery frame (already
exercised in tests/test_gateway.py) that parses successfully and is the
correct frame type to trigger discovery.
"""
import functools
from superlink.bridge.core import BridgeCore
from superlink.bridge.store import InMemoryDeviceStore
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.session import DeviceSession
from superlink.bridge.events import DeviceDiscovered
from tests.fixtures.captured_frames import (
    SENSOR_MAC, DEFAULT_PAIRING_KEY, DISCOVERY_FRAME_RAW,
)

GW_MAC = bytes.fromhex("0102030405")


def _make_session(record):
    return DeviceSession(record, gw_mac=GW_MAC, pairing_key=DEFAULT_PAIRING_KEY,
                         profiles=ProfileRegistry.load())


def _core(auto_adopt):
    factory = functools.partial(_make_session)
    return BridgeCore(InMemoryDeviceStore(), ProfileRegistry.load(),
                      session_factory=factory, auto_adopt=auto_adopt)


def test_unknown_frame_discovers():
    core = _core(auto_adopt=False)
    seen = []
    core.subscribe(seen.append)
    core.feed(DISCOVERY_FRAME_RAW, channel=1, now=1.0)
    assert any(isinstance(e, DeviceDiscovered) and e.mac == SENSOR_MAC for e in seen)


def test_two_macs_no_crosstalk():
    core = _core(auto_adopt=True)
    other = bytearray(DISCOVERY_FRAME_RAW)
    other[2:8] = bytes.fromhex("AABBCCDDEEFF")
    seen = []
    core.subscribe(seen.append)
    core.feed(DISCOVERY_FRAME_RAW, channel=1, now=1.0)
    core.feed(bytes(other), channel=1, now=1.0)
    assert set(core._sessions.keys()) == {SENSOR_MAC, bytes.fromhex("AABBCCDDEEFF")}
    # Real per-MAC session objects, not shared state.
    assert core._sessions[SENSOR_MAC] is not core._sessions[bytes.fromhex("AABBCCDDEEFF")]
    assert isinstance(core._sessions[SENSOR_MAC], DeviceSession)
    assert core._sessions[SENSOR_MAC].mac == SENSOR_MAC
    assert core._sessions[bytes.fromhex("AABBCCDDEEFF")].mac == bytes.fromhex("AABBCCDDEEFF")
