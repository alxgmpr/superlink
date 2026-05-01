"""
Mock UniFi controller — Y4 active driver.

Drives a real Ubiquiti SuperLink bridge through the captured Y3 pair
script: bridgeInfoGet → keyExchange → authorize → discoveryStart →
addDevice → 3-burst (0x53/0x44/grant) → on grant-ack from sensor →
removeDevice → addDevice (rotated) → post-rotation burst → ACTIVE.

The bridge is a TLS WebSocket *server* on port 8571. We connect in as
the controller using the bridge's own lorabr.cert/key (self-signed
CN=localhost trust pool), negotiate Sec-WebSocket-Protocol: ucp4 with
permessage-deflate, then speak UBNT JSON-RPC.

Wire framing (verified against captures/live/y3/bridge_y3_pair_20260429.log):

    01 01 00 00 00 00 LEN_HI LEN_LO  <LEN-byte JSON envelope>
    02 01 00 00 00 00 LEN_HI LEN_LO  <LEN-byte JSON payload>

Each application message is one (envelope, payload) pair. Multiple pairs
may be concatenated in one WS frame. The first prefix byte (0x01 / 0x02)
distinguishes envelope from payload; LEN is 16-bit big-endian.

Run:

    /Users/alex/superlink/.venv/bin/python tools/mock_controller/server.py \\
        --bridge 10.1.1.141:8571 --active

In passive mode (without --active) the mock only logs RX traffic — useful
to confirm the bridge accepts the connection without driving any state.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import secrets
import ssl
import sys
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

try:
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed
except ImportError:
    sys.exit("pip install 'websockets>=12'")

import hashlib

try:
    import nacl.bindings as nacl_bindings
except ImportError:
    sys.exit("pip install pynacl")


log = logging.getLogger("mock-controller")


# ---------------------------------------------------------------------------
# SuperLink LoRa application-layer codec.
#
# Recovered 2026-04-30 from static RE of UniFi Protect (UNVR fw v5.0.16,
# webpack module 41118 = ./src/middleware/devices/loraBridges/helpers/
# applicationLayer/messages.ts). Full reference at
# docs/protocol/superlink_application_layer.md.
#
# A message on the wire is:
#     [1B messageId] [1B messageTag] [N-byte payload]
# ---------------------------------------------------------------------------

# MessageId enum values we use.
MSG_ADOPT_REQUEST = 0x02
MSG_ADOPT_RESPONSE = 0x03

# 32B salt baked into Protect's deviceAdopt KDF (deviceAdopt.ts).
KDF_SALT_H = bytes.fromhex(
    "70be68514ce7b81328d9f3215855c5675336ea88a08a728df7fce95cc8970a59"
)


def kdf_E(my_priv: bytes, their_pub: bytes) -> bytes:
    """Persistent-key KDF from Protect's deviceAdopt.ts.

        E(my_priv, their_pub) = blake2b32(
            X25519(my_priv, their_pub)
            || base × my_priv
            || their_pub
            || H )
    """
    if len(my_priv) != 32 or len(their_pub) != 32:
        raise ValueError("expected 32-byte priv/pub")
    shared = nacl_bindings.crypto_scalarmult(my_priv, their_pub)
    my_pub = nacl_bindings.crypto_scalarmult_base(my_priv)
    return hashlib.blake2b(
        shared + my_pub + their_pub + KDF_SALT_H, digest_size=32
    ).digest()


def encode_adopt_request(
    message_tag: int,
    gw_pub: bytes,
    gw_fb_pub: bytes,
    network_id: int,
) -> bytes:
    """Build the 70-byte ADOPT_REQUEST wire body."""
    if len(gw_pub) != 32 or len(gw_fb_pub) != 32:
        raise ValueError("pubkeys must be 32 bytes")
    return (
        bytes([MSG_ADOPT_REQUEST, message_tag & 0xFF])
        + gw_pub
        + gw_fb_pub
        + network_id.to_bytes(4, "big")
    )


def decode_adopt_response(body: bytes) -> tuple[int, bytes, bytes]:
    """Parse a 66-byte ADOPT_RESPONSE. Returns (messageTag, devicePub, deviceFbPub)."""
    if len(body) < 66 or body[0] != MSG_ADOPT_RESPONSE:
        raise ValueError(f"not an ADOPT_RESPONSE (len={len(body)}, id=0x{body[:1].hex()})")
    return body[1], body[2:34], body[34:66]


# ---------------------------------------------------------------------------
# UBNT framing
# ---------------------------------------------------------------------------

PRIMARY_KIND = 0x01    # envelope (request / response / event)
SECONDARY_KIND = 0x02  # payload (params / result / event body)


def encode_pair(envelope: dict, payload: dict) -> bytes:
    """Serialise an (envelope, payload) tuple into UBNT wire bytes."""
    return _frame(PRIMARY_KIND, envelope) + _frame(SECONDARY_KIND, payload)


def _frame(kind: int, obj: dict) -> bytes:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > 0xFFFF:
        raise ValueError(f"body too long ({len(body)} > 65535)")
    return bytes([kind, 0x01, 0x00, 0x00, 0x00, 0x00]) + len(body).to_bytes(2, "big") + body


def decode_frame(buf: bytes) -> list[tuple[int, dict]]:
    """Decode a WS payload into [(kind, json_dict), ...].

    Stops at the first malformed boundary and warns. Decoded objects with
    bad JSON come back as {"_decode_error": ..., "_raw_hex": ...}.
    """
    out: list[tuple[int, dict]] = []
    i = 0
    while i < len(buf):
        if len(buf) - i < 8:
            log.warning("trailing %d bytes < 8-byte prefix", len(buf) - i)
            break
        kind = buf[i]
        if kind not in (PRIMARY_KIND, SECONDARY_KIND):
            log.warning("unexpected prefix kind 0x%02x at offset %d", kind, i)
            break
        body_len = int.from_bytes(buf[i + 6 : i + 8], "big")
        if len(buf) - i - 8 < body_len:
            log.warning("truncated body: want %d got %d", body_len, len(buf) - i - 8)
            break
        body = buf[i + 8 : i + 8 + body_len]
        try:
            obj = json.loads(body)
        except Exception as e:
            log.warning("JSON decode failed: %s body=%r", e, body)
            obj = {"_decode_error": str(e), "_raw_hex": body.hex()}
        out.append((kind, obj))
        i += 8 + body_len
    return out


# ---------------------------------------------------------------------------
# Sensor DB — captured ground truth from Y3 pair (2026-04-29)
# ---------------------------------------------------------------------------


@dataclass
class Sensor:
    mac_no_colons: str            # uppercase hex, no separators
    mac_with_colons: str          # uppercase hex with colons
    persistent_key: str           # 64-hex addDevice.key for the pair-completing call
    state: str = "DISCOVERED"     # DISCOVERED → PAIRING → BURSTED → ROTATED → ACTIVE
    # Ephemeral X25519 privates the controller picks for this pair attempt's
    # ADOPT_REQUEST. Set in send_pair_burst, consumed in on_grant_ack to derive
    # the rotated addDevice.key/fallbackKey from the sensor's ADOPT_RESPONSE.
    eph_priv_r: bytes | None = None
    eph_priv_o: bytes | None = None


TEST_SENSOR = Sensor(
    mac_no_colons="9041B22E9A53",
    mac_with_colons="90:41:B2:2E:9A:53",
    persistent_key="c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db",
)


# networkId baked into ADOPT_REQUEST (= getShortConsoleId in Protect). Captured
# value for our test bridge; controller has one of these per console.
NETWORK_ID = 0x048F  # 1167

# Default first NN. The captured Y3 0x53 reply was 099a; aligning here means
# the third burst message (the ADOPT_REQUEST) lands on NN=0x9c which matched
# the captured trace. NN value isn't load-bearing now that we build the
# ADOPT_REQUEST dynamically — kept for parity with prior captures.
DEFAULT_NN_START = 0x9A


# ---------------------------------------------------------------------------
# MockController
# ---------------------------------------------------------------------------


class MockController:
    # The bridge keeps a per-clientID (BRIDGE_SALT, AUTH_TOKEN) pair from
    # adoption time. We only have the constants for the real UniFi
    # controller's UUID; using a fresh UUID would trigger first-use
    # provisioning we can't currently fake. With this UUID we also need
    # the real controller blocked or the bridge will reject with
    # errorCode 12 "Duplicate connection".
    CLIENT_ID = "652ee9b0-8ea3-41a9-8589-b601159ea6b6"

    # Per-bridge constants captured live (2026-04-29) via keyhook on lorabrd.
    # The bridge generates the per-connection authorize.secret encryption key
    # via:
    #   key = BLAKE2b-32(shared_x25519 || ctl_pub || bridge_pub || BRIDGE_SALT)
    # then runs crypto_secretbox_open_easy(secret, nonce=ZEROS||"UBNU", key)
    # and memcmps the plaintext against AUTH_TOKEN. Both constants stayed
    # the same across two fresh authorize captures, so they're per-bridge
    # state (likely set during initial UniFi adoption). For a different
    # bridge we'd need to re-capture.
    BRIDGE_SALT = bytes.fromhex(
        "69b1d4a63a301106494473b25c23c372a1ba54fbbdbd4fd47ed638460e425f07"
    )
    # AUTH_TOKEN is the plaintext that gets encrypted into authorize.secret.
    # The protocol is a self-rotating chain: every successful authorize, the
    # bridge ships the NEXT round's expected PT encrypted in the response's
    # `secret` field (NONCE_tail "UBNV" instead of "UBNU"). The mock decrypts
    # it (see bootstrap()) and stores it as the new AUTH_TOKEN for the next
    # connect.
    #
    # The value below is the most recent one we know works. If it goes stale
    # (e.g. between sessions while mock isn't running), the next authorize
    # will fail with errorCode 4 — but if KEYHOOK_BYPASS_AUTH=1 is set on the
    # bridge's lorabrd, the bypass lets the first authorize through and we
    # capture a fresh token from the response for the next reconnect.
    AUTH_TOKEN = bytes.fromhex(
        "1315740706b7eb7f0eb925af76a805a5c9dd6912836680acaefff77e27f8e3ae"
    )
    # 24-byte nonce: 20 zero bytes + ASCII "UBNU". Same nonce as the
    # documented connection-challenge crypto in crypto_keys_captured.md.
    AUTHORIZE_NONCE = b"\x00" * 20 + b"UBNU"
    # Same key, different nonce: bridge encrypts the next-session EXPECTED with
    # this and ships it in the authorize response's `secret` field.
    NEXT_TOKEN_NONCE = b"\x00" * 20 + b"UBNV"

    def __init__(
        self,
        *,
        log_path: Path | None,
        active: bool,
        nn_start: int = DEFAULT_NN_START,
    ):
        self.log_path = log_path
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        self.active = active
        self.dl_counter = nn_start & 0xFF
        # Copy template so per-controller state (e.g. .state) doesn't leak
        # across instances (or across tests that share the module-level table).
        self.sensors: dict[str, Sensor] = {
            TEST_SENSOR.mac_no_colons.lower(): replace(TEST_SENSOR),
        }
        # request_id → Future((envelope, payload)) for pending requests we sent.
        self.pending: dict[str, asyncio.Future] = {}
        self.bridge_id: str | None = None
        self.radio_ready: bool = False

    def next_nn(self) -> int:
        nn = self.dl_counter
        self.dl_counter = (nn + 1) & 0xFF
        return nn

    # -- logging -----------------------------------------------------------

    def log_pair(self, direction: str, env: dict, pay: dict) -> None:
        entry = {"ts": time.time(), "dir": direction, "env": env, "pay": pay}
        if self.log_path:
            with self.log_path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        action = env.get("action") or env.get("name") or env.get("type") or "?"
        ident = (env.get("id") or "")[:8]
        preview = json.dumps(pay, separators=(",", ":"))
        log.info("%s %-16s id=%s pay=%s", direction, action, ident, preview[:160])

    # -- raw send ----------------------------------------------------------

    async def send_pair(self, ws, env: dict, pay: dict) -> None:
        wire = encode_pair(env, pay)
        await ws.send(wire)
        self.log_pair("TX", env, pay)

    # -- request/response correlation -------------------------------------

    async def request(
        self, ws, action: str, params: dict, timeout: float = 30.0
    ) -> tuple[dict, dict]:
        """Send a controller→bridge request and await the response.

        Returns (response_envelope, response_payload). Raises asyncio.TimeoutError
        on timeout, RuntimeError on bridge-reported error.
        """
        msg_id = str(uuid.uuid4())
        envelope = {
            "action": action,
            "id": msg_id,
            "type": "request",
            "timestamp": int(time.time() * 1000),
        }
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pending[msg_id] = future
        try:
            await self.send_pair(ws, envelope, params)
            env, pay = await asyncio.wait_for(future, timeout=timeout)
            err = env.get("error") or ""
            if err:
                raise RuntimeError(f"{action} failed: {err} (errorCode={env.get('errorCode')})")
            return env, pay
        finally:
            self.pending.pop(msg_id, None)

    async def fire_and_forget(self, ws, action: str, params: dict) -> str:
        """Send a controller→bridge request without awaiting the response.

        Returns the request id. Used for sendMessage where the response is
        delayed by tens of seconds (waiting on LoRa ACK).
        """
        msg_id = str(uuid.uuid4())
        envelope = {
            "action": action,
            "id": msg_id,
            "type": "request",
            "timestamp": int(time.time() * 1000),
        }
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pending[msg_id] = future
        await self.send_pair(ws, envelope, params)
        # Future stays pending; we drop it on completion.
        return msg_id

    def complete_response(self, env: dict, pay: dict) -> None:
        msg_id = env.get("id")
        f = self.pending.get(msg_id)
        if f is not None and not f.done():
            f.set_result((env, pay))
        else:
            err = env.get("error") or ""
            if err:
                log.warning("delayed sendMessage error id=%s err=%r", msg_id, err)

    # -- bootstrap ---------------------------------------------------------

    async def bootstrap(self, ws) -> None:
        """Replicate the captured controller bootstrap.

        bridgeInfoGet → keyExchange → authorize → discoveryStart.

        Raises RuntimeError if the bridge's radio is not ready, mirroring
        the real controller's "Interface down" path; the connect loop will
        reconnect with backoff.
        """
        _, info = await self.request(ws, "bridgeInfoGet", {})
        self.bridge_id = info.get("id")
        radios = info.get("ifaces", {})
        self.radio_ready = bool(radios.get("radio0", {}).get("isReady", False))
        log.info("bridge_id=%s radio_ready=%s", self.bridge_id, self.radio_ready)
        if not self.radio_ready:
            # Same path the real controller takes: bail and reconnect.
            raise RuntimeError("bridge radio not ready (isReady=false)")

        # keyExchange.key is the controller's ephemeral X25519 pubkey — the
        # bridge runs scalarmult against it on the bridge-side priv to derive
        # the shared secret used as input to the authorize secretbox key.
        import pysodium  # local import to keep the optional dep tidy
        ctl_kx_priv = secrets.token_bytes(32)
        ctl_kx_pub = pysodium.crypto_scalarmult_curve25519_base(ctl_kx_priv)

        _, kx_resp = await self.request(
            ws, "keyExchange", {"key": ctl_kx_pub.hex()}
        )
        bridge_kx_pub = bytes.fromhex(kx_resp["key"])

        # Reproduce the bridge-side crypto chain (verified live via keyhook
        # on lorabrd 2026-04-29):
        #   shared = X25519(ctl_kx_priv, bridge_kx_pub)
        #   key    = blake2b-32(shared || ctl_pub || bridge_pub || BRIDGE_SALT)
        #   secret = base64(secretbox_easy(AUTH_TOKEN, nonce=ZEROS+"UBNU", key))
        shared = pysodium.crypto_scalarmult_curve25519(ctl_kx_priv, bridge_kx_pub)
        kdf_input = shared + ctl_kx_pub + bridge_kx_pub + self.BRIDGE_SALT
        secretbox_key = pysodium.crypto_generichash(kdf_input, outlen=32)
        secret_blob = pysodium.crypto_secretbox(
            self.AUTH_TOKEN, self.AUTHORIZE_NONCE, secretbox_key
        )
        secret = base64.b64encode(secret_blob).decode("ascii")
        log.debug(
            "authorize crypto:\n"
            "  ctl_priv = %s\n  ctl_pub  = %s\n  br_pub   = %s\n"
            "  shared   = %s\n  kdf_in   = %s\n  key      = %s\n"
            "  ct       = %s\n  pt       = %s",
            ctl_kx_priv.hex(), ctl_kx_pub.hex(), bridge_kx_pub.hex(),
            shared.hex(), kdf_input.hex(), secretbox_key.hex(),
            secret_blob.hex(), self.AUTH_TOKEN.hex(),
        )

        _, auth_resp = await self.request(
            ws, "authorize", {"clientID": self.CLIENT_ID, "secret": secret}
        )

        # The bridge ships the NEXT-session AUTH_TOKEN encrypted in the
        # authorize response payload as
        #   {"iface":"radio0","secret":base64(secretbox(NEXT_AUTH_TOKEN,
        #                                              ZEROS+"UBNV",
        #                                              session_key))}
        # We decrypt it and stash for the next reconnect — that's how the
        # protocol bootstraps without a hardcoded shared secret. Verified
        # live: NEXT_AUTH_TOKEN equals the value the bridge memcmp's against
        # next time, so reconnecting with this PT authorizes naturally.
        next_b64 = auth_resp.get("secret")
        if next_b64:
            try:
                next_ct = base64.b64decode(next_b64)
                next_pt = pysodium.crypto_secretbox_open(
                    next_ct, self.NEXT_TOKEN_NONCE, secretbox_key
                )
                if len(next_pt) == 32:
                    log.info("captured NEXT_AUTH_TOKEN: %s", next_pt.hex())
                    self.__class__.AUTH_TOKEN = next_pt
                else:
                    log.warning("next-token PT wrong size: %d", len(next_pt))
            except Exception as e:
                log.warning("failed to decrypt authorize response secret: %s", e)
        else:
            log.debug("authorize response had no `secret` field")

        await self.request(ws, "discoveryStart", {})
        log.info("✓ bootstrap complete; awaiting bridge events")

    # -- event handlers ----------------------------------------------------

    async def handle_event(self, ws, env: dict, pay: dict) -> None:
        name = env.get("name", "")
        if name == "discoveryResult":
            await self.on_discoveryResult(ws, pay)
        elif name == "devsInfoChanged":
            log.debug("devsInfoChanged: %s", pay)
        elif name == "messageReceived":
            await self.on_messageReceived(ws, pay)
        else:
            log.warning("unhandled event name=%s pay=%s", name, pay)

    async def on_discoveryResult(self, ws, pay: dict) -> None:
        mac = pay.get("mac", "").replace(":", "").lower()
        adopted = bool(pay.get("adopted", False))
        sensor = self.sensors.get(mac)
        if not sensor:
            log.info("discoveryResult for unknown sensor %s adopted=%s", mac, adopted)
            return
        if adopted:
            if sensor.state != "ACTIVE":
                sensor.state = "ACTIVE"
                log.info("🎉 sensor %s reached ACTIVE state", mac)
            return
        # adopted=false — start the pair flow if we haven't already
        if sensor.state != "DISCOVERED":
            return
        log.info("starting pair for sensor %s", mac)
        sensor.state = "PAIRING"
        try:
            await self.send_addDevice(ws, sensor, sensor.persistent_key, fallback=None)
            await self.send_pair_burst(ws, sensor)
            sensor.state = "BURSTED"
        except Exception as e:
            log.exception("pair kickoff failed for %s: %s", mac, e)
            sensor.state = "DISCOVERED"

    async def send_addDevice(
        self, ws, sensor: Sensor, key: str, fallback: str | None
    ) -> None:
        params: dict[str, Any] = {"mac": sensor.mac_no_colons, "key": key}
        if fallback:
            params["fallbackKey"] = fallback
        # Fire-and-forget: bridge syslog (2026-04-30 phase 2) shows the
        # bridge takes ~90s to ack addDevice — it waits for the LoRa
        # session-key handshake with the sensor to complete before responding.
        # We don't need to block on that: the captured Y3 trace shows the
        # 3-burst follows addDevice within ms (the bridge accepts the burst
        # and queues it as DL the moment session is up). If we await the ack
        # we either race against it (90s timeout) or block our own burst,
        # leaving the sensor with no grant payload to ACK.
        await self.fire_and_forget(ws, "addDevice", params)

    async def send_sendMessage_data(self, ws, sensor: Sensor, data_hex: str) -> str:
        """Push raw DL bytes via fire-and-forget sendMessage."""
        params = {
            "mac": sensor.mac_no_colons,
            "data": data_hex,
            "duty": True,
            "ack": True,
            "timeout": 900000,
        }
        return await self.fire_and_forget(ws, "sendMessage", params)

    async def send_pair_burst(self, ws, sensor: Sensor) -> None:
        """Y3 pair-completing burst: 0x53 + 0x44 + ADOPT_REQUEST.

        The third message is a freshly built `ADOPT_REQUEST` (messageId=0x02)
        per docs/protocol/superlink_application_layer.md. We pick fresh
        ephemeral X25519 privates `r` and `o` per pair attempt, store them
        on the sensor for use in on_grant_ack (which derives the rotated
        addDevice.key/fallbackKey from the sensor's ADOPT_RESPONSE).

        NNs increment per message; the third message's NN becomes the
        ADOPT_REQUEST's messageTag (echoed by the sensor in its
        ADOPT_RESPONSE for correlation).
        """
        nn0 = self.next_nn()
        nn1 = self.next_nn()
        nn2 = self.next_nn()

        # Fresh ephemeral keypair per pair attempt — DON'T reuse across
        # retries or the rotated addDevice values won't match what the
        # sensor derives.
        sensor.eph_priv_r = secrets.token_bytes(32)
        sensor.eph_priv_o = secrets.token_bytes(32)
        gw_pub = nacl_bindings.crypto_scalarmult_base(sensor.eph_priv_r)
        gw_fb_pub = nacl_bindings.crypto_scalarmult_base(sensor.eph_priv_o)

        adopt_req = encode_adopt_request(nn2, gw_pub, gw_fb_pub, NETWORK_ID)
        log.info(
            "ADOPT_REQUEST tag=0x%02x gw_pub=%s gw_fb=%s networkId=0x%x",
            nn2, gw_pub.hex(), gw_fb_pub.hex(), NETWORK_ID,
        )

        await self.send_sendMessage_data(ws, sensor, f"09{nn0:02x}")
        await self.send_sendMessage_data(ws, sensor, f"0b{nn1:02x}11010d14")
        await self.send_sendMessage_data(ws, sensor, adopt_req.hex())

    async def on_messageReceived(self, ws, pay: dict) -> None:
        mac = pay.get("mac", "").replace(":", "").lower()
        data_hex = (pay.get("data") or "").lower()
        sensor = self.sensors.get(mac)
        if not sensor:
            log.info("messageReceived for unknown sensor %s", mac)
            return
        if not data_hex:
            return
        first = int(data_hex[:2], 16)
        body_len = len(data_hex) // 2
        log.info("UL %s inner=0x%02x len=%d", mac, first, body_len)

        if first == 0x0a:
            # Sensor 0x44 management UL — controller replies with 0x4e + 0x44.
            await self.send_management_replies(ws, sensor)
        elif first == 0x03:
            # 66B ADOPT_RESPONSE — extract the sensor's two fresh ephemeral
            # pubkeys and feed them into the rotation step.
            if sensor.state == "BURSTED":
                try:
                    body = bytes.fromhex(data_hex)
                except ValueError as exc:
                    log.error("malformed ADOPT_RESPONSE hex: %s", exc)
                    return
                try:
                    tag, dev_pub, dev_fb_pub = decode_adopt_response(body)
                except ValueError as exc:
                    log.error("ADOPT_RESPONSE decode: %s", exc)
                    return
                log.info(
                    "ADOPT_RESPONSE tag=0x%02x devicePub=%s deviceFbPub=%s",
                    tag, dev_pub.hex(), dev_fb_pub.hex(),
                )
                await self.on_grant_ack(ws, sensor, dev_pub, dev_fb_pub)
        elif first == 0x0c:
            # Telemetry from sensor in ACTIVE state. Real controller eventually
            # replies with a 0x44 management; mock keeps quiet to avoid drowning
            # the LoRa duty cycle. Bridge will surface the next 0x0a UL when the
            # sensor next reports.
            log.debug("telemetry %s len=%d", mac, body_len)
        else:
            log.info("UL inner=0x%02x not handled (data=%s)", first, data_hex[:32])

    async def send_management_replies(self, ws, sensor: Sensor) -> None:
        nn0 = self.next_nn()
        nn1 = self.next_nn()
        await self.send_sendMessage_data(ws, sensor, f"0e{nn0:02x}0d00012c")
        await self.send_sendMessage_data(ws, sensor, f"0b{nn1:02x}11010d14")

    async def on_grant_ack(
        self, ws, sensor: Sensor, dev_pub: bytes, dev_fb_pub: bytes,
    ) -> None:
        """Sensor returned ADOPT_RESPONSE — derive new persistent keys and rotate."""
        if not sensor.eph_priv_r or not sensor.eph_priv_o:
            log.error("on_grant_ack but no ephemeral state for %s", sensor.mac_no_colons)
            return

        # Run the persistent-key KDF on both halves (deviceAdopt.ts in Protect).
        new_key      = kdf_E(sensor.eph_priv_r, dev_pub).hex()
        new_fallback = kdf_E(sensor.eph_priv_o, dev_fb_pub).hex()
        log.info(
            "rotated keys derived: key=%s fallbackKey=%s",
            new_key, new_fallback,
        )
        # Discard the ephemeral privates — they MUST NOT be reused for any
        # future pair attempt (would defeat the per-pair-fresh property).
        sensor.eph_priv_r = None
        sensor.eph_priv_o = None

        # Same fire-and-forget reasoning as send_addDevice — the bridge
        # processes Remove instantly (visible in syslog) but the JSON-RPC
        # response is delayed/missing.
        await self.fire_and_forget(ws, "removeDevice", {"mac": sensor.mac_no_colons})
        await self.send_addDevice(
            ws, sensor, new_key, fallback=new_fallback,
        )
        # Y3 post-rotation burst: 09 NN, 0b NN+1, 09 NN+2 (NNs 9f/a0/a1 in capture)
        nn0 = self.next_nn()
        nn1 = self.next_nn()
        nn2 = self.next_nn()
        await self.send_sendMessage_data(ws, sensor, f"09{nn0:02x}")
        await self.send_sendMessage_data(ws, sensor, f"0b{nn1:02x}11010d14")
        await self.send_sendMessage_data(ws, sensor, f"09{nn2:02x}")
        sensor.state = "ROTATED"

    # -- main receiver loop ------------------------------------------------

    async def receiver(self, ws) -> None:
        async for raw in ws:
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            msgs = decode_frame(raw)
            i = 0
            while i + 1 < len(msgs):
                env_kind, env = msgs[i]
                pay_kind, pay = msgs[i + 1]
                if env_kind == PRIMARY_KIND and pay_kind == SECONDARY_KIND:
                    self.log_pair("RX", env, pay)
                    msg_type = env.get("type")
                    if msg_type == "response":
                        self.complete_response(env, pay)
                    elif msg_type == "event":
                        await self.handle_event(ws, env, pay)
                    elif msg_type == "request":
                        log.warning("unexpected request from bridge: %s", env)
                    i += 2
                else:
                    log.warning(
                        "unexpected pair kinds env=0x%02x pay=0x%02x",
                        env_kind, pay_kind,
                    )
                    i += 1


# ---------------------------------------------------------------------------
# Connect loop
# ---------------------------------------------------------------------------


async def run_session(args, ctl: MockController) -> None:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    if args.client_cert and args.client_key:
        ssl_ctx.load_cert_chain(certfile=args.client_cert, keyfile=args.client_key)
        log.info("presenting client cert %s", args.client_cert)

    url = f"wss://{args.bridge}/"
    log.info("connecting to %s", url)

    async with connect(
        url,
        ssl=ssl_ctx,
        compression="deflate",
        subprotocols=["ucp4"],
        open_timeout=10,
        close_timeout=2,
        ping_interval=20,
        ping_timeout=10,
        max_size=2**20,
    ) as ws:
        log.info("connected; running %s loop", "active" if ctl.active else "passive")
        recv_task = asyncio.create_task(ctl.receiver(ws))
        try:
            if ctl.active:
                # Bootstrap concurrently with the receiver, since bridgeInfoGet
                # response comes through the receiver path.
                await ctl.bootstrap(ws)
            await recv_task
        finally:
            recv_task.cancel()


async def main_loop(args) -> None:
    ctl = MockController(
        log_path=Path(args.log) if args.log else None,
        active=args.active,
        nn_start=int(args.nn_start, 0),
    )
    backoff = 1.0
    while True:
        try:
            await run_session(args, ctl)
            log.info("session closed cleanly")
        except (ConnectionClosed, OSError) as e:
            log.warning("connection error: %s", e)
        except RuntimeError as e:
            log.warning("session aborted: %s", e)
        except Exception:
            log.exception("unexpected error in session")
        if args.no_reconnect:
            return
        log.info("reconnecting in %.1fs", backoff)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 1.5, 30.0)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--bridge", default="10.1.1.141:8571",
                   help="bridge host:port (lorabrd TLS WS listener)")
    p.add_argument("--client-cert",
                   default="tools/mock_controller/bridge_certs/lorabr.cert")
    p.add_argument("--client-key",
                   default="tools/mock_controller/bridge_certs/lorabr.key")
    p.add_argument("--log", default="captures/live/mock_controller.jsonl")
    p.add_argument("--active", action="store_true",
                   help="Drive bootstrap + pair flow. Without this flag the "
                        "mock connects passively and only logs incoming traffic.")
    p.add_argument("--nn-start", default=hex(DEFAULT_NN_START),
                   help=f"Starting NN counter (default {hex(DEFAULT_NN_START)} "
                        "matches captured Y3 trace; not load-bearing now that "
                        "the ADOPT_REQUEST is built dynamically)")
    p.add_argument("--no-reconnect", action="store_true",
                   help="Exit after a single session instead of looping with backoff")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.active:
        log.warning(
            "ACTIVE mode — make sure the real UniFi controller cannot reach "
            "this bridge during the test. Block 10.1.1.1 at the bridge or "
            "run on an isolated LAN."
        )

    try:
        asyncio.run(main_loop(args))
    except KeyboardInterrupt:
        log.info("shutdown")


if __name__ == "__main__":
    main()
