"""
ssl_decode.py — Decode keyhook SSL_read/SSL_write blocks into JSON-RPC.

The keyhook (keyhook.c) logs every plaintext SSL_read / SSL_write call as
blocks of the form:

    FUNC=ssl_read|ssl_write[_ex]
    SSL=<ptr>
    RA=<ra>
    LEN=<n>
    DATA=<hex>
    ---

This script:
  1. Parses the log into per-SSL-connection streams, separated by direction.
  2. Reassembles WebSocket frames (RFC 6455) — handles 7/16/64-bit length
     forms and unmasks client-to-server frames.
  3. Inflates RSV1=1 (permessage-deflate, RFC 7692) payloads using context
     takeover semantics (a single inflate stream per direction per
     connection, fed each frame's payload + the 4-byte
     `00 00 ff ff` deflate-block-end suffix per RFC 7692 §7.2.2).
  4. Strips the 8-byte UBNT framing prefix from each application message
     and emits records of the form:
        {"conn": "<ssl_ptr>", "dir": "rx"|"tx", "type": "<1-char>",
         "json": {...}, "raw_hex": "..."}

Usage:
    python ssl_decode.py captures/live/y3/bridge_y3_idle_t0.log
        > captures/live/y3/bridge_y3_idle_t0.ndjson

Notes:
  - The bridge is the WS server. RX (= ssl_read) is client-to-server and
    therefore MASKED. TX (= ssl_write) is unmasked.
  - WS continuation frames (opcode 0x0) carry a continuation of the prior
    application message; we accumulate by direction.
  - Close frames (0x8), ping (0x9), pong (0xA) are emitted as control
    records without JSON parsing.
"""

from __future__ import annotations

import argparse
import json
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# Keyhook log parsing
# ---------------------------------------------------------------------------


@dataclass
class SslEvent:
    func: str          # "ssl_read" | "ssl_write" | "ssl_read_ex" | "ssl_write_ex"
    ssl: str           # hex pointer string, e.g. "0014e1a0"
    ra: str
    length: int
    data: bytes
    order: int         # original sequence index in the log


def parse_keyhook_log(path: Path) -> list[SslEvent]:
    """Yield SslEvent objects in original log order (which matches wire order
    per SSL pointer / direction, since SSL_read/SSL_write are serialised
    against the underlying socket)."""
    out: list[SslEvent] = []
    text = path.read_text(errors="replace")
    blocks = text.split("---\n")
    order = 0
    for block in blocks:
        if not block.strip():
            continue
        fields: dict[str, str] = {}
        for line in block.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                fields[k.strip()] = v.strip()
        func = fields.get("FUNC", "")
        if not func.startswith("ssl_"):
            continue
        try:
            n = int(fields.get("LEN", "0"))
            data = bytes.fromhex(fields.get("DATA", ""))
        except ValueError:
            continue
        out.append(SslEvent(
            func=func,
            ssl=fields.get("SSL", ""),
            ra=fields.get("RA", ""),
            length=n,
            data=data,
            order=order,
        ))
        order += 1
    return out


# ---------------------------------------------------------------------------
# Per-connection / per-direction stream reassembly
# ---------------------------------------------------------------------------


@dataclass
class Stream:
    buf: bytearray = field(default_factory=bytearray)
    # WS-level continuation accumulator (across continuation frames within
    # a single application message).
    msg_payload: bytearray = field(default_factory=bytearray)
    msg_opcode: int = 0
    msg_compressed: bool = False
    # permessage-deflate context-takeover decompressor (one per direction
    # per connection). Lazily initialised on first compressed frame.
    inflater: zlib._Decompress | None = None  # type: ignore[name-defined]
    # State machine: 0 = pre-handshake (HTTP), 1 = WS frames
    in_ws: bool = False


def feed_stream(stream: Stream, chunk: bytes) -> Iterator[dict]:
    """Append chunk to stream and yield one decoded record per complete
    HTTP request/response or WebSocket message."""
    stream.buf += chunk
    while True:
        if not stream.in_ws:
            # Look for end of HTTP headers
            i = stream.buf.find(b"\r\n\r\n")
            if i < 0:
                return
            head = bytes(stream.buf[:i + 4])
            del stream.buf[:i + 4]
            yield {
                "kind": "http",
                "raw": head.decode("latin-1", errors="replace"),
            }
            stream.in_ws = True
            continue
        # WS frame: at minimum 2 bytes
        if len(stream.buf) < 2:
            return
        b0 = stream.buf[0]
        b1 = stream.buf[1]
        fin = (b0 & 0x80) != 0
        rsv1 = (b0 & 0x40) != 0
        opcode = b0 & 0x0f
        masked = (b1 & 0x80) != 0
        plen = b1 & 0x7f
        hdr = 2
        if plen == 126:
            if len(stream.buf) < 4:
                return
            plen = int.from_bytes(stream.buf[2:4], "big")
            hdr = 4
        elif plen == 127:
            if len(stream.buf) < 10:
                return
            plen = int.from_bytes(stream.buf[2:10], "big")
            hdr = 10
        if masked:
            if len(stream.buf) < hdr + 4:
                return
            mask = bytes(stream.buf[hdr:hdr + 4])
            hdr += 4
        else:
            mask = b""
        if len(stream.buf) < hdr + plen:
            return
        payload = bytes(stream.buf[hdr:hdr + plen])
        del stream.buf[:hdr + plen]
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        # Continuation handling
        if opcode == 0x0:
            stream.msg_payload += payload
        elif opcode in (0x1, 0x2):
            stream.msg_payload = bytearray(payload)
            stream.msg_opcode = opcode
            stream.msg_compressed = rsv1
        elif opcode == 0x8:
            yield {"kind": "close", "payload_hex": payload.hex()}
            continue
        elif opcode in (0x9, 0xA):
            yield {"kind": "ping" if opcode == 0x9 else "pong",
                   "payload_hex": payload.hex()}
            continue
        else:
            yield {"kind": "unknown_opcode", "opcode": opcode,
                   "payload_hex": payload.hex()}
            continue
        if fin:
            full = bytes(stream.msg_payload)
            if stream.msg_compressed:
                if stream.inflater is None:
                    # RFC 7692 §7.2.2: use raw deflate (no zlib header), and
                    # append `00 00 ff ff` to each message payload before
                    # inflating to terminate the deflate block.
                    stream.inflater = zlib.decompressobj(-zlib.MAX_WBITS)
                full = stream.inflater.decompress(full + b"\x00\x00\xff\xff")
            yield {
                "kind": "message",
                "opcode": stream.msg_opcode,
                "compressed": stream.msg_compressed,
                "payload": full,
            }
            stream.msg_payload = bytearray()


# ---------------------------------------------------------------------------
# UBNT framing prefix split + JSON parse
# ---------------------------------------------------------------------------


def split_ubnt_messages(payload: bytes) -> list[dict]:
    """An application message is one or more concatenated tuples of:
        <8-byte framing prefix> <JSON object>
    where the 8th byte of the prefix is the type code (one of 'r'/'o'/'q'/'J'
    seen so far). Returns a list of {"type", "json", "raw_hex"} dicts."""
    out: list[dict] = []
    i = 0
    while i < len(payload):
        # Heuristic: scan forward for the next '{' which marks JSON start.
        j = payload.find(b"{", i)
        if j < 0:
            if i < len(payload):
                out.append({"type": None, "json": None,
                            "raw_hex": payload[i:].hex(), "note": "trailing-non-json"})
            break
        # The byte immediately before the '{' is the type code.
        type_byte = chr(payload[j - 1]) if j > 0 else None
        # Bracket-balance scan to find end of JSON object.
        depth = 0
        end = j
        in_str = False
        esc = False
        for k in range(j, len(payload)):
            c = payload[k]
            if esc:
                esc = False
                continue
            if c == 0x5c:  # backslash
                esc = True
                continue
            if c == 0x22:  # quote
                in_str = not in_str
                continue
            if in_str:
                continue
            if c == 0x7b:
                depth += 1
            elif c == 0x7d:
                depth -= 1
                if depth == 0:
                    end = k + 1
                    break
        if depth != 0:
            out.append({"type": type_byte, "json": None,
                        "raw_hex": payload[i:].hex(), "note": "unbalanced-json"})
            break
        try:
            obj = json.loads(payload[j:end].decode("utf-8"))
        except Exception as e:
            obj = None
            out.append({"type": type_byte, "json": None,
                        "raw_hex": payload[j:end].hex(),
                        "note": f"json-parse-fail: {e}"})
            i = end
            continue
        out.append({"type": type_byte, "json": obj,
                    "raw_hex": payload[j:end].hex()})
        i = end
    return out


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------


def decode(events: list[SslEvent]) -> Iterator[dict]:
    streams: dict[tuple[str, str], Stream] = {}
    for ev in events:
        direction = "rx" if "read" in ev.func else "tx"
        key = (ev.ssl, direction)
        st = streams.setdefault(key, Stream())
        for rec in feed_stream(st, ev.data):
            base = {"order": ev.order, "conn": ev.ssl, "dir": direction,
                    "ra": ev.ra}
            if rec["kind"] == "http":
                yield {**base, "kind": "http", "raw": rec["raw"]}
            elif rec["kind"] == "message":
                msgs = split_ubnt_messages(rec["payload"])
                for m in msgs:
                    yield {**base, "kind": "ws_msg",
                           "compressed": rec["compressed"],
                           "opcode": rec["opcode"],
                           **m}
            else:
                yield {**base, **rec}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("log", type=Path)
    p.add_argument("--pretty", action="store_true",
                   help="human-readable summary instead of NDJSON")
    args = p.parse_args()
    events = parse_keyhook_log(args.log)
    if args.pretty:
        for rec in decode(events):
            tag = f"[{rec['order']:03d}] {rec['conn']} {rec['dir']:2s}"
            kind = rec.get("kind", "?")
            if kind == "http":
                first = rec["raw"].splitlines()[0] if rec["raw"] else ""
                print(f"{tag} HTTP {first!r}")
            elif kind == "ws_msg":
                t = rec.get("type")
                cmp = "Z" if rec.get("compressed") else " "
                if rec.get("json") is not None:
                    j = json.dumps(rec["json"], separators=(",", ":"))
                    print(f"{tag} {cmp} type={t!r} {j[:240]}")
                else:
                    print(f"{tag} {cmp} type={t!r} RAW={rec.get('raw_hex','')[:100]} ({rec.get('note')})")
            else:
                print(f"{tag} {kind} {rec.get('payload_hex','')[:64]}")
    else:
        for rec in decode(events):
            # Drop bytes objects for JSON output
            r = dict(rec)
            print(json.dumps(r, default=str))


if __name__ == "__main__":
    main()
