"""
Mock UniFi controller for USL Bridge (lorabrd).

Architecture correction (2026-04-21): lorabrd listens on port 8571 of
the bridge as a TLS WebSocket SERVER. The UniFi controller is the
CLIENT that connects in, sends JSON-RPC requests, and receives events.

So this module connects OUT to the bridge, completes the TLS handshake
against the bridge's self-signed cert (CN=localhost, served from
`/etc/persistent/lorabr.cert`), does the WebSocket upgrade, and starts
speaking the JSON-RPC envelope protocol.

Run:
    source .venv/bin/activate
    python tools/mock_controller/server.py --bridge 10.1.1.141:8571

You may need to block the real controller from connecting first (e.g.
firewall the controller's IP) or the bridge may reject a second
client connection.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import ssl
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

try:
    import websockets
    from websockets.asyncio.client import connect, ClientConnection
except ImportError:
    sys.exit("pip install 'websockets>=12'")


log = logging.getLogger("mock-controller")


# ---------------------------------------------------------------------------
# Envelope framing
# ---------------------------------------------------------------------------
# Observed real-controller frames have the layout:
#   <8-byte length/flags prefix> <1-byte type> {json}
# sometimes multiple (type, json) tuples concatenated in one WS frame.
# Type byte:
#   'r' = response, 'o' = event/oneway, 'J' = result payload accompanying
#        a response. Framing prefix exact layout is TBD but the 8-byte
#        fixed value below was observed repeatedly.

FRAME_PREFIX = bytes.fromhex("0101000000000000")
TYPE_RESPONSE = b"r"
TYPE_EVENT = b"o"
TYPE_RESULT = b"J"


def split_messages(payload: bytes) -> list[tuple[bytes, dict]]:
    out: list[tuple[bytes, dict]] = []
    i = 0
    while i < len(payload):
        j = payload.find(b"{", i)
        if j < 0:
            break
        type_byte = payload[j - 1 : j] if j > 0 else b""
        depth = 0
        end = j
        in_str = False
        esc = False
        for k in range(j, len(payload)):
            c = payload[k : k + 1]
            if esc:
                esc = False
                continue
            if c == b"\\":
                esc = True
                continue
            if c == b'"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if c == b"{":
                depth += 1
            elif c == b"}":
                depth -= 1
                if depth == 0:
                    end = k + 1
                    break
        if depth != 0:
            break
        try:
            obj = json.loads(payload[j:end].decode("utf-8"))
            out.append((type_byte, obj))
        except Exception as e:
            log.warning("JSON decode failed at %d..%d: %s", j, end, e)
        i = end
    return out


def build_envelope_bytes(messages: Iterable[tuple[bytes, dict]]) -> bytes:
    """Concatenate (type, obj) tuples into a single WS frame."""
    out = bytearray()
    for msg_type, obj in messages:
        out += FRAME_PREFIX
        out += msg_type
        out += json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return bytes(out)


# ---------------------------------------------------------------------------
# Controller state / canned replies
# ---------------------------------------------------------------------------


class MockController:
    """Minimum state + canned responses to drive the bridge.

    Pre-seeded with the test sensor captured in pair6/7. Extend by
    observing what method names the bridge calls and what JSON fields
    appear in the bridge's outbound traffic.
    """

    SENSOR_DB: dict[str, dict[str, Any]] = {
        "9041b22e9a53": {
            "mac_colons": "90:41:B2:2E:9A:53",
            "keypair_0x30": bytes.fromhex(
                "c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db"
            ),
            "network_id": 1167,
            "ssid": 44692,
        },
    }

    BRIDGE_DEFAULTS = {
        "network_id": 1167,
        "ssid": 44692,
        # Captured real-controller value (base64-encoded 48B). Whether the
        # bridge validates this content or treats it as opaque is TBD.
        "radio_secret": (
            "89lFNDa1DU7vCrg5Ob6/DRkD0aKO3H4QolZB0GNfed9K02gaO+QDc48sL6kYQHal"
        ),
    }

    def __init__(self, log_path: Path | None = None):
        self.log_path = log_path
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_json(self, direction: str, type_byte: bytes, obj: dict) -> None:
        entry = {
            "ts": time.time(),
            "dir": direction,
            "type": type_byte.decode("latin-1", errors="replace"),
            "obj": obj,
        }
        if self.log_path:
            with self.log_path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        preview = json.dumps(obj, separators=(",", ":"))[:200]
        log.info("%s %s %s", direction, type_byte, preview)

    def response_for(self, request_obj: dict) -> list[tuple[bytes, dict]]:
        """Return outbound messages to send after receiving a bridge-side
        request. Empty list if nothing to send."""
        msg_id = request_obj.get("id") or str(uuid.uuid4())
        method = request_obj.get("method") or request_obj.get("name") or ""

        envelope = {
            "id": msg_id,
            "timestamp": int(time.time() * 1000),
            "type": "response",
            "error": "",
            "errorCode": 0,
        }
        result: dict[str, Any] | None = None

        params = request_obj.get("params") or {}
        mac = (params.get("mac") or "9041B22E9A53").lower().replace(":", "")

        if method in ("getDeviceKey", "startSessionKeyRenewal", "getKey"):
            sensor = self.SENSOR_DB.get(mac)
            if sensor:
                result = {"key": sensor["keypair_0x30"].hex().upper()}
            else:
                import secrets
                result = {"key": secrets.token_hex(32).upper()}
                log.warning("Unknown sensor %s — returning random key", mac)
        elif method in ("getInterfaceSecret", "getSecret"):
            result = {"iface": "radio0",
                      "secret": self.BRIDGE_DEFAULTS["radio_secret"]}
        elif method:
            log.warning("Unknown method %r — ack with empty result", method)

        out: list[tuple[bytes, dict]] = [(TYPE_RESPONSE, envelope)]
        if result is not None:
            out.append((TYPE_RESULT, result))
        for t, o in out:
            self.log_json("TX", t, o)
        return out


# ---------------------------------------------------------------------------
# WebSocket client
# ---------------------------------------------------------------------------


async def run_client(args: argparse.Namespace) -> None:
    ctl = MockController(log_path=Path(args.log) if args.log else None)

    # Accept bridge's self-signed server cert, present a client cert
    # (bridge trusts certs matching its `controller.crt` / self-signed
    # CN=localhost pool; lorabr.cert+key was observed to succeed as a
    # client cert during openssl s_client probing).
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    if args.client_cert and args.client_key:
        ssl_ctx.load_cert_chain(certfile=args.client_cert, keyfile=args.client_key)
        log.info("presenting client cert %s", args.client_cert)

    url = f"wss://{args.bridge}/"
    log.info("connecting to bridge at %s", url)

    async with connect(
        url,
        ssl=ssl_ctx,
        compression="deflate",
        subprotocols=["ucp4"],          # bridge requires ucp4 subprotocol
        additional_headers={"X-Mode": "0"},
        open_timeout=10,
        close_timeout=2,
        ping_interval=20,
        ping_timeout=10,
    ) as ws:
        log.info("connected; WS handshake succeeded")

        # Optionally kick the bridge with a synthetic event to probe
        # what it expects first.
        # (commented; enable once we know what method to call)
        # await ws.send(build_envelope_bytes([
        #     (TYPE_EVENT, {"id": str(uuid.uuid4()),
        #                   "name": "hello",
        #                   "type": "event",
        #                   "timestamp": int(time.time() * 1000)})
        # ]))

        async for raw in ws:
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            log.debug("raw recv %d bytes: %s", len(raw),
                      raw[:96].hex() + ("..." if len(raw) > 96 else ""))
            for type_byte, obj in split_messages(raw):
                ctl.log_json("RX", type_byte, obj)
                if type_byte in (TYPE_EVENT, b""):
                    # Event from bridge — we ack with silent response to
                    # keep the session alive. Some events require specific
                    # handling that we'll add as we see them.
                    continue
                replies = ctl.response_for(obj)
                if replies:
                    await ws.send(build_envelope_bytes(replies))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--bridge", default="10.1.1.141:8571",
                   help="bridge host:port (lorabrd TLS WS listener)")
    p.add_argument("--client-cert",
                   default="tools/mock_controller/bridge_certs/lorabr.cert",
                   help="client cert file (bridge's own lorabr.cert works)")
    p.add_argument("--client-key",
                   default="tools/mock_controller/bridge_certs/lorabr.key",
                   help="client key file")
    p.add_argument("--log", default="captures/live/mock_controller.jsonl")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        asyncio.run(run_client(args))
    except KeyboardInterrupt:
        log.info("shutdown")
    except Exception:
        log.exception("fatal")


if __name__ == "__main__":
    main()
