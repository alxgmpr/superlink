"""Unit tests for tools/mock_controller/server.py.

Covers:
  - UBNT framing round-trip (encode_pair → decode_frame).
  - Decoded prefix bytes match the format observed in captures
    (01/02 01 00 00 00 00 LEN_HI LEN_LO).
  - 16-bit length encoding for bodies > 255 bytes.
  - Decoder fail-safe behaviour on malformed input.
  - MockController state-machine transitions through a synthetic pair script.

Run:
    /Users/alex/superlink/.venv/bin/python -m pytest tests/test_mock_controller.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

# Add tools/mock_controller/ to import path so we can `import server`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "mock_controller"))

import server as mc  # noqa: E402


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------


def test_encode_pair_layout():
    env = {"type": "request"}
    pay = {"key": "v"}
    wire = mc.encode_pair(env, pay)

    # Two 8-byte prefixes + two JSON bodies.
    e_body = json.dumps(env, separators=(",", ":")).encode()
    p_body = json.dumps(pay, separators=(",", ":")).encode()
    assert wire[:6] == bytes([mc.PRIMARY_KIND, 0x01, 0, 0, 0, 0])
    assert wire[6:8] == len(e_body).to_bytes(2, "big")
    assert wire[8 : 8 + len(e_body)] == e_body
    off = 8 + len(e_body)
    assert wire[off : off + 6] == bytes([mc.SECONDARY_KIND, 0x01, 0, 0, 0, 0])
    assert wire[off + 6 : off + 8] == len(p_body).to_bytes(2, "big")
    assert wire[off + 8 :] == p_body


def test_round_trip_simple():
    env = {"action": "bridgeInfoGet", "id": "abc", "type": "request",
           "timestamp": 1234}
    pay: dict = {}
    wire = mc.encode_pair(env, pay)
    decoded = mc.decode_frame(wire)
    assert decoded == [(mc.PRIMARY_KIND, env), (mc.SECONDARY_KIND, pay)]


def test_round_trip_long_body():
    """Body > 255 bytes exercises the high byte of the 16-bit length."""
    env = {"type": "response", "id": "x"}
    # ~ 280 bytes
    pay = {"data": "A" * 260}
    wire = mc.encode_pair(env, pay)

    p_body_len = len(json.dumps(pay, separators=(",", ":")))
    assert p_body_len > 0xFF
    # Find the secondary prefix and confirm its 2-byte BE length.
    secondary_off = wire.index(bytes([mc.SECONDARY_KIND, 0x01, 0, 0, 0, 0]))
    assert int.from_bytes(wire[secondary_off + 6 : secondary_off + 8], "big") == p_body_len

    decoded = mc.decode_frame(wire)
    assert decoded == [(mc.PRIMARY_KIND, env), (mc.SECONDARY_KIND, pay)]


def test_decode_concatenated_pairs():
    """Multiple (envelope, payload) pairs in one WS frame, as the bridge does."""
    a_env = {"action": "addDevice", "id": "1", "type": "request"}
    a_pay = {"mac": "AA"}
    b_env = {"action": "sendMessage", "id": "2", "type": "request"}
    b_pay = {"mac": "AA", "data": "0992"}
    wire = mc.encode_pair(a_env, a_pay) + mc.encode_pair(b_env, b_pay)
    decoded = mc.decode_frame(wire)
    assert decoded == [
        (mc.PRIMARY_KIND, a_env),
        (mc.SECONDARY_KIND, a_pay),
        (mc.PRIMARY_KIND, b_env),
        (mc.SECONDARY_KIND, b_pay),
    ]


def test_decode_unknown_kind_stops():
    bogus = bytes([0xFF, 0x01, 0, 0, 0, 0, 0, 2]) + b"{}"
    assert mc.decode_frame(bogus) == []


def test_decode_truncated_body():
    """If a body is short the decoder stops before the broken record."""
    e_body = b'{"a":1}'
    good = (
        bytes([mc.PRIMARY_KIND, 0x01, 0, 0, 0, 0])
        + len(e_body).to_bytes(2, "big")
        + e_body
    )
    truncated = (
        bytes([mc.SECONDARY_KIND, 0x01, 0, 0, 0, 0])
        + (50).to_bytes(2, "big")  # claims 50 bytes
        + b"{}"  # only 2
    )
    decoded = mc.decode_frame(good + truncated)
    assert decoded == [(mc.PRIMARY_KIND, {"a": 1})]


def test_encode_oversize_raises():
    with pytest.raises(ValueError):
        mc.encode_pair({"x": "X" * 70000}, {})


# ---------------------------------------------------------------------------
# Captured-bytes spot checks
# ---------------------------------------------------------------------------


def test_known_y3_envelope_prefix():
    """Verify our framing matches the prefix bytes captured in Y3 pair log.

    From captures/live/y3/bridge_y3_pair_20260429.log order=13 tx, the
    bridgeInfoGet response (114-byte envelope) had prefix 01 01 00 00 00 00 00 72.
    """
    env = {
        "error": "",
        "errorCode": 0,
        "id": "f166bf48-9d57-457f-a3cb-d8e4aa79e4d0",
        "timestamp": 1777490677489,
        "type": "response",
    }
    pay: dict = {}
    wire = mc.encode_pair(env, pay)
    e_body = json.dumps(env, separators=(",", ":")).encode()
    assert len(e_body) == 114
    assert wire[:8] == bytes.fromhex("0101000000000072")


def test_known_y3_long_body_prefix():
    """Bridge-info response body with caps was 282 bytes → prefix 02 01 ... 01 1a."""
    pay = {
        "defaultIface": "radio0",
        "id": "8dccbbb6-367f-4098-8c7a-e214b674fb6f",
        "ifaces": {
            "radio0": {
                "caps": {"maxDataLen": 241, "spectralScan": True},
                "driver": "sx1302",
                "isReady": True,
                "mac": "90:41:B2:34:83:DC",
                "part": "SX1302",
                "vendor": "Semtech",
            }
        },
        "runtime": 5,
        "type": "LoRa-Bridge",
        "version": "1.1.0",
    }
    body = json.dumps(pay, separators=(",", ":")).encode()
    assert len(body) == 282
    wire = mc._frame(mc.SECONDARY_KIND, pay)
    assert wire[:8] == bytes.fromhex("020100000000011a")


# ---------------------------------------------------------------------------
# State-machine: synthetic pair script
# ---------------------------------------------------------------------------


class _FakeWS:
    """Minimal WebSocket stand-in that captures sent frames and lets the
    test inject responses by completing the pending Future for an id."""

    def __init__(self, ctl: mc.MockController):
        self.sent: list[bytes] = []
        self.ctl = ctl
        # When set, every send() call automatically completes the matching
        # pending Future with this canned (env, pay) pair.
        self.auto_response: tuple[dict, dict] | None = None

    async def send(self, data) -> None:
        self.sent.append(data)
        # Decode what we sent and auto-ack any request for which a response
        # is registered (or, if auto_response is set, a generic ack).
        if isinstance(data, str):
            data = data.encode()
        msgs = mc.decode_frame(data)
        for kind, obj in msgs:
            if kind == mc.PRIMARY_KIND and obj.get("type") == "request":
                if self.auto_response is not None:
                    env, pay = self.auto_response
                    env = {**env, "id": obj["id"]}
                    self.ctl.complete_response(env, pay)
                else:
                    # Default: empty success response.
                    self.ctl.complete_response(
                        {"error": "", "errorCode": 0, "id": obj["id"],
                         "type": "response", "timestamp": 0},
                        {},
                    )

    def decoded_sent_pairs(self) -> list[tuple[dict, dict]]:
        """Yield (envelope, payload) tuples from everything we sent so far."""
        out = []
        for blob in self.sent:
            msgs = mc.decode_frame(blob)
            i = 0
            while i + 1 < len(msgs):
                e_k, e_o = msgs[i]
                p_k, p_o = msgs[i + 1]
                assert e_k == mc.PRIMARY_KIND and p_k == mc.SECONDARY_KIND
                out.append((e_o, p_o))
                i += 2
        return out


def _make_ctl() -> mc.MockController:
    return mc.MockController(log_path=None, active=True, nn_start=0x9A)


def test_pair_burst_replays_captured_grant():
    """After kickoff the mock should fire 099a, 0b9b..., 029c... in order."""
    ctl = _make_ctl()
    ws = _FakeWS(ctl)

    # Trigger pair: simulate discoveryResult adopted=false from the bridge.
    asyncio.run(ctl.on_discoveryResult(
        ws, {"mac": mc.TEST_SENSOR.mac_with_colons,
             "adopted": False, "ssid": 44692,
             "signal": {"rssi": -57, "snr": 9}},
    ))

    pairs = ws.decoded_sent_pairs()
    actions = [(e["action"], p) for e, p in pairs]
    assert actions[0][0] == "addDevice"
    assert actions[0][1]["mac"] == mc.TEST_SENSOR.mac_no_colons
    assert actions[0][1]["key"] == mc.TEST_SENSOR.persistent_key
    assert "fallbackKey" not in actions[0][1]

    # 3-burst follows: 0x53 (09 NN), 0x44 (0b NN+1 ...), 0x74 grant.
    assert actions[1][0] == "sendMessage"
    assert actions[1][1]["data"] == "099a"
    assert actions[2][0] == "sendMessage"
    assert actions[2][1]["data"] == "0b9b11010d14"
    assert actions[3][0] == "sendMessage"
    assert actions[3][1]["data"] == mc.TEST_SENSOR.grant_data
    # NN at position 1 of the grant body.
    assert actions[3][1]["data"][2:4] == "9c"

    sensor = ctl.sensors[mc.TEST_SENSOR.mac_no_colons.lower()]
    assert sensor.state == "BURSTED"
    # NN counter advanced 3.
    assert ctl.dl_counter == (0x9A + 3) & 0xFF


def test_management_reply_after_0a_ul():
    """A messageReceived starting 0x0a (sensor 0x44 management) → 0e + 0b reply."""
    ctl = _make_ctl()
    ws = _FakeWS(ctl)
    # Skip past pair burst — pretend we're already in BURSTED state, NN=0x9d.
    sensor = ctl.sensors[mc.TEST_SENSOR.mac_no_colons.lower()]
    sensor.state = "BURSTED"
    ctl.dl_counter = 0x9D

    asyncio.run(ctl.on_messageReceived(
        ws, {"mac": mc.TEST_SENSOR.mac_with_colons,
             "data": "0A9DAE940001000100010CB24D9D04",  # truncated 0x0a UL
             "signal": {"rssi": -57, "snr": 9}},
    ))
    pairs = ws.decoded_sent_pairs()
    datas = [p["data"] for e, p in pairs if e["action"] == "sendMessage"]
    assert datas == ["0e9d0d00012c", "0b9e11010d14"]


def test_grant_ack_triggers_rotation():
    """A messageReceived starting 0x03 in BURSTED state → removeDevice +
    addDevice rotated + post-rotation burst."""
    ctl = _make_ctl()
    ws = _FakeWS(ctl)
    sensor = ctl.sensors[mc.TEST_SENSOR.mac_no_colons.lower()]
    sensor.state = "BURSTED"
    ctl.dl_counter = 0x9F  # captured post-rotation NN

    asyncio.run(ctl.on_messageReceived(
        ws, {"mac": mc.TEST_SENSOR.mac_with_colons,
             "data": "039C8F0F12DE419E",  # truncated 0x03 grant ack
             "signal": {"rssi": -54, "snr": 8}},
    ))
    pairs = ws.decoded_sent_pairs()
    actions = [(e["action"], p) for e, p in pairs]
    # removeDevice → addDevice (rotated) → 09 NN → 0b NN+1 → 09 NN+2
    assert actions[0][0] == "removeDevice"
    assert actions[0][1] == {"mac": mc.TEST_SENSOR.mac_no_colons}
    assert actions[1][0] == "addDevice"
    assert actions[1][1]["key"] == mc.TEST_SENSOR.rotated_key
    assert actions[1][1]["fallbackKey"] == mc.TEST_SENSOR.rotated_fallback_key
    assert actions[2][1]["data"] == "099f"
    assert actions[3][1]["data"] == "0ba011010d14"
    assert actions[4][1]["data"] == "09a1"
    assert sensor.state == "ROTATED"


def test_adopted_true_marks_active():
    ctl = _make_ctl()
    ws = _FakeWS(ctl)
    sensor = ctl.sensors[mc.TEST_SENSOR.mac_no_colons.lower()]
    sensor.state = "ROTATED"
    asyncio.run(ctl.on_discoveryResult(
        ws,
        {"mac": mc.TEST_SENSOR.mac_with_colons, "adopted": True,
         "networkId": 1167, "ssid": 44692, "signal": {"rssi": -57, "snr": 9}},
    ))
    assert sensor.state == "ACTIVE"
    # No outgoing traffic from this transition.
    assert ws.sent == []


def test_unknown_sensor_ignored():
    ctl = _make_ctl()
    ws = _FakeWS(ctl)
    asyncio.run(ctl.on_discoveryResult(
        ws, {"mac": "AABBCCDDEEFF", "adopted": False, "ssid": 1},
    ))
    assert ws.sent == []


def test_grant_nn_patch_when_misaligned():
    """If nn_start is offset, the burst should patch the grant body's NN byte
    rather than send a stale value the sensor would reject."""
    ctl = mc.MockController(log_path=None, active=True, nn_start=0x40)
    ws = _FakeWS(ctl)
    asyncio.run(ctl.on_discoveryResult(
        ws, {"mac": mc.TEST_SENSOR.mac_with_colons, "adopted": False, "ssid": 1},
    ))
    pairs = ws.decoded_sent_pairs()
    grant_pay = next(
        p for e, p in pairs
        if e["action"] == "sendMessage" and len(p["data"]) == 140
    )
    # nn_start=0x40 → nn0=40 (0x53), nn1=41 (0x44), nn2=42 (grant)
    assert grant_pay["data"][:4] == "0242"
    # Trailer untouched.
    assert grant_pay["data"][-8:] == "0000048f"
