"""PROPERTY_REQUEST sweep controller.

Drives a memory-disclosure fuzz of a paired SuperLink sensor: hand out
batches of property ids to probe via PROPERTY_REQUEST, then classify the
PROPERTY_REPORTs that come back. The high-value signal is an *undefined*
property id (one the firmware doesn't define, i.e. not in
appmsg.DEFINED_PROPERTY_IDS) that nonetheless returns bytes — a candidate
out-of-bounds read in the sensor's property dispatch.

Pure logic, no RF. The gateway state machine feeds it decoded reports and
pulls id batches to encode into DL frames.
"""

from __future__ import annotations

from . import appmsg


def parse_id_spec(spec: str) -> list[int]:
    """Parse a property-id selection into a sorted id list.

    Accepts "all" (0-255), "undefined" (0-255 minus firmware-defined ids), or
    a comma list of singles and inclusive ranges, e.g. "0,18,43-255".
    """
    spec = spec.strip().lower()
    if spec == "all":
        return list(range(256))
    if spec == "undefined":
        return sorted(set(range(256)) - appmsg.DEFINED_PROPERTY_IDS)
    ids: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            rng = range(lo, hi + 1)
        else:
            rng = [int(part)]
        for i in rng:
            if not 0 <= i <= 255:
                raise ValueError(f"id {i} out of range 0-255")
            ids.append(i)
    return ids


# Firmware-defined message ids (module 41118 MessageId enum). Undefined ids —
# 0x00, 0x0d, and 0x12..0xff — are the dispatch-table fuzz targets.
DEFINED_MESSAGE_IDS = frozenset(
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17})
# Never send these unsolicited: they reboot / factory-reset / re-adopt the
# sensor and would tear down the session.
DANGEROUS_MESSAGE_IDS = frozenset({2, 6, 7})


def parse_msg_id_spec(spec: str) -> list[int]:
    """Parse a message-id selection. "undefined" = 0x00,0x0d,0x12..0xff;
    "all" = 0..255 minus dangerous (reboot/reset/adopt); or a comma list of
    singles and inclusive ranges."""
    spec = spec.strip().lower()
    if spec == "undefined":
        return sorted(set(range(256)) - DEFINED_MESSAGE_IDS
                      - DANGEROUS_MESSAGE_IDS)
    if spec == "all":
        return [i for i in range(256) if i not in DANGEROUS_MESSAGE_IDS]
    ids: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            rng = range(lo, hi + 1)
        else:
            rng = [int(part)]
        for i in rng:
            if not 0 <= i <= 255:
                raise ValueError(f"msg id {i} out of range 0-255")
            ids.append(i)
    return ids


class MessageSweep:
    """Fuzz the sensor's message dispatch: send each message id as
    `[msgId][tag][body]` and record the response (matched by tag). An undefined
    opcode that returns anything other than a plain status/no-reply is the
    signal — a candidate handler-table over-index."""

    sustain_on_any = True  # any 0x44 response keeps the ping-pong going

    def __init__(self, ids=None, body: bytes = b""):
        self._queue = (list(ids) if ids is not None else
                       sorted(set(range(256)) - DEFINED_MESSAGE_IDS
                              - DANGEROUS_MESSAGE_IDS))
        self.body = bytes(body)
        self._pending: dict[int, int] = {}   # tag -> msg id sent
        self._probed: list[int] = []
        self.responses: dict[int, dict] = {}  # msg id -> {resp_msg_id, payload}
        self.findings: list[dict] = []

    def next_probe(self, tag: int) -> bytes | None:
        if not self._queue:
            return None
        mid = self._queue.pop(0)
        self._probed.append(mid)
        self._pending[tag & 0xFF] = mid
        return bytes([mid, tag & 0xFF]) + self.body

    def ingest(self, payload: bytes) -> None:
        if not payload or len(payload) < 2:
            return
        resp_id, resp_tag = payload[0], payload[1]
        mid = self._pending.pop(resp_tag, None)
        if mid is None:
            return  # not a reply to one of our probes (telemetry / PING)
        body = payload[2:]
        self.responses[mid] = {"resp_msg_id": resp_id, "payload": bytes(body)}
        # A plain REQUEST_STATUS_RESPONSE (0x01) with no body-of-interest is the
        # boring "unsupported" answer. Anything else — a different opcode echoed
        # back, or a non-empty body — is worth flagging.
        interesting = resp_id != 0x01 or len(body) > 1
        if interesting:
            self.findings.append({
                "msg_id": mid, "resp_msg_id": resp_id,
                "payload": bytes(body)})

    def done(self) -> bool:
        return not self._queue

    def summary(self) -> dict:
        return {"probed": len(self._probed), "remaining": len(self._queue),
                "responded": len(self.responses), "findings": len(self.findings)}


class PingProbe:
    """PING_REQUEST with varying data lengths; compares PING_RESPONSE data
    length to what was sent. A response longer than the request is a
    Heartbleed-style over-read leaking sensor memory."""

    sustain_on_any = True

    def __init__(self, lengths=None):
        self._queue = list(lengths) if lengths else [0, 1, 4, 16, 64, 200]
        self._pending: dict[int, int] = {}   # tag -> sent length
        self._probed: list[int] = []
        self.results: list[dict] = []
        self.findings: list[dict] = []

    def next_probe(self, tag: int) -> bytes | None:
        if not self._queue:
            return None
        n = self._queue.pop(0)
        self._probed.append(n)
        self._pending[tag & 0xFF] = n
        # Distinctive, position-dependent marker so an over-read is obvious.
        marker = bytes([0xA0 + (i & 0x0F) for i in range(n)])
        return appmsg.encode_ping_request(tag=tag, data=marker)

    def ingest(self, payload: bytes) -> None:
        if not payload or len(payload) < 2:
            return
        if payload[0] != appmsg.MessageId.PING_RESPONSE:
            return
        sent = self._pending.pop(payload[1], None)
        if sent is None:
            return
        data = bytes(payload[2:])
        leak = len(data) > sent
        rec = {"sent": sent, "resp_len": len(data), "leak": leak,
               "hex": data.hex()}
        self.results.append(rec)
        if leak:
            self.findings.append(rec)

    def done(self) -> bool:
        return not self._queue

    def summary(self) -> dict:
        return {"probed": len(self._probed), "remaining": len(self._queue),
                "results": len(self.results), "findings": len(self.findings)}


class KeepAwake:
    """Holds the sensor awake indefinitely by keeping it in its command window
    — sends a PING every exchange, forever, so the CPU never deep-sleeps. This
    lets a plain SWD attach land on the running app (live keys resident) instead
    of falling back to connect-under-reset, and lets the OTA-chunk differential
    dump run while the sensor is awake."""

    sustain_on_any = True

    def __init__(self):
        self.pings = 0
        self.responses = 0
        self.findings: list = []

    def next_probe(self, tag: int) -> bytes | None:
        self.pings += 1
        return appmsg.encode_ping_request(tag=tag)

    def ingest(self, payload: bytes) -> None:
        if payload and len(payload) >= 2 and payload[0] == 0x05:
            self.responses += 1

    def done(self) -> bool:
        return False   # never — stay awake until the gateway stops

    def summary(self) -> dict:
        return {"pings": self.pings, "responses": self.responses}


def build_fuzz_corpus() -> list:
    """Crafted app-message bodies targeting the sensor's message parser, below
    the well-behaved app API. Each is `[msgId][tag=0][payload]`; the harness
    patches byte 1 with a live tag so responses correlate.

    Ordered least→most aggressive (safe reads first, buffer-overflow attempts
    last) since a bad case can crash/brick the single sensor.
    """
    T = 0x00
    cases: list[tuple[str, bytes]] = []

    def add(name, body):
        cases.append((name, bytes(body)))

    # --- length-field OVER-READ: the payoff case ---------------------------
    # PROPERTY_SET dynamic value = [0e][tag][id][channel][len][value…]. We send
    # a big `len` but only a couple value bytes. If the firmware copies `len`
    # bytes without bounding to the received frame, it over-reads adjacent
    # RX-buffer/stack memory and — if it stores + echoes the value in the
    # PROPERTY_REPORT confirmation — leaks that memory to us. Disclosure with
    # no SWD needed.
    for pid in (0x01, 0x0d, 0x0f, 0x20, 0x2a):
        for claim in (0x10, 0x20, 0x40, 0x80, 0xf0):
            add(f"pset-overread id=0x{pid:02x} len=0x{claim:02x}",
                [0x0e, T, pid, 0x00, claim, 0xAA, 0xBB])
    # PROPERTY_REPORT/SET with a truncated trailing entry (missing value bytes).
    add("pset-truncated-entry", [0x0e, T, 0x0d, 0x00])

    # --- mid-size structural / undefined cases (safe frame sizes) ----------
    add("undef-0x0d-bigbody", [0x0d, T] + [0x55] * 0x40)
    add("undef-0x00-bigbody", [0x00, T] + [0x66] * 0x40)
    add("preq-200ids", [0x0b, T] + list(range(200)))
    add("dinfo-report-wrongdir", [0x0a, T, 0x00])      # 0a is device→ctl
    add("fw-chunk-resp-garbage", [0x11, T] + [0] * 8 + [0x90] * 16)

    # --- oversized / boundary (LAST — biggest brick/crash risk) ------------
    # The SX1302 TX tops out just under a 256B frame (238B PING data → 254B
    # frame works; 240B → 256B fails). Stay at 224B data (frame ~240B) to probe
    # a large echo/copy buffer without tripping the concentrator's own limit.
    for n in (0xC0, 0xD0, 0xE0):                       # 192,208,224 data bytes
        add(f"ping-{n:#x}", [0x04, T] + [0xC0 + (i & 0xF) for i in range(n)])
    add("pset-oversize-value", [0x0e, T, 0x0d, 0x00, 0xDC] + [0x41] * 0xDC)
    return cases


class FuzzHarness:
    """Sends a corpus of crafted/malformed app messages and flags anomalous
    responses — the RF-input side of instrumented frame fuzzing. A response
    longer than what we sent is an over-read (memory disclosure); an unexpected
    opcode or a mid-run session drop (sensor reset/crash) is also a signal."""

    sustain_on_any = True

    def __init__(self, cases=None):
        self._queue = list(cases) if cases is not None else build_fuzz_corpus()
        self._pending: dict[int, tuple] = {}   # tag -> (name, sent body)
        self._probed: list[str] = []
        self.responses: list[dict] = []
        self.findings: list[dict] = []

    def next_probe(self, tag: int) -> bytes | None:
        if not self._queue:
            return None
        name, body = self._queue.pop(0)
        b = bytearray(body)
        if len(b) >= 2:
            b[1] = tag & 0xFF
        self._pending[tag & 0xFF] = (name, bytes(b))
        self._probed.append(name)
        return bytes(b)

    def ingest(self, payload: bytes) -> None:
        if not payload or len(payload) < 2:
            return
        resp_id, resp_tag = payload[0], payload[1]
        pend = self._pending.pop(resp_tag, None)
        if pend is None:
            return
        name, sent = pend
        body = payload[2:]
        sent_payload_len = max(0, len(sent) - 2)
        rec = {"case": name, "resp_id": resp_id, "resp_len": len(body),
               "sent_len": sent_payload_len, "hex": body.hex()}
        self.responses.append(rec)
        # Over-read: response body carries more than we handed the sensor.
        # Unexpected opcode (not status/ping/report) is also worth a look.
        if len(body) > sent_payload_len or resp_id not in (0x01, 0x05, 0x0c):
            self.findings.append(rec)

    def done(self) -> bool:
        return not self._queue

    def summary(self) -> dict:
        return {"probed": len(self._probed), "remaining": len(self._queue),
                "responses": len(self.responses), "findings": len(self.findings)}


class PropertySweep:
    def __init__(self, ids=None, batch_size: int = 8):
        # Default: probe the entire byte range (defined ids give a baseline,
        # undefined ids are the actual targets).
        self._queue = list(range(256)) if ids is None else list(ids)
        self.batch_size = batch_size
        self.sizes: dict = {}
        self.anonymous_device_id: bytes | None = None
        self.device_info: dict | None = None
        # Ids the *device* advertises supporting (subset of firmware-defined).
        # None until a DEVICE_INFO_REPORT is ingested.
        self.advertised: set | None = None
        self._probed: list[int] = []
        # propertyId -> {"value", "channel", "known"} for ids that answered.
        self.responses: dict[int, dict] = {}
        self.findings: list[dict] = []

    # ---- driving the sweep ----

    def next_batch(self) -> list[int]:
        """Return the next batch of ids to probe (marking them probed)."""
        batch = self._queue[:self.batch_size]
        self._queue = self._queue[self.batch_size:]
        self._probed.extend(batch)
        return batch

    def done(self) -> bool:
        return not self._queue

    def set_device_info(self, report: dict) -> None:
        """Record a decoded DEVICE_INFO_REPORT: value-size map + device id."""
        self.device_info = report
        self.sizes = appmsg.property_sizes(report)
        self.anonymous_device_id = report.get("anonymousDeviceId")
        self.advertised = {p["propertyId"]
                           for p in report.get("supportedProperties", [])}

    # ---- classifying responses ----

    def record_report(self, report: dict) -> None:
        """Ingest a decoded PROPERTY_REPORT and flag disclosures."""
        for prop in report.get("properties", []):
            pid = prop["propertyId"]
            value = prop.get("value", b"")
            self.responses[pid] = {
                "channel": prop.get("channel"),
                "value": value,
                "known": prop.get("known", True),
            }
            reasons = self._classify(pid, value)
            if reasons:
                self.findings.append({
                    "propertyId": pid,
                    "name": appmsg.property_name(pid),
                    "channel": prop.get("channel"),
                    "value": value,
                    "reasons": reasons,
                })

    def _classify(self, pid: int, value: bytes) -> list[str]:
        reasons = []
        if not value:
            return reasons
        if pid not in appmsg.DEFINED_PROPERTY_IDS:
            # Firmware doesn't define this id, yet it returned data — the
            # strongest out-of-bounds-read signal.
            reasons.append("undefined_property_id")
        elif self.advertised is not None and pid not in self.advertised:
            # A firmware-defined id the device did NOT advertise supporting,
            # yet it answered with data — weaker, but worth a look.
            reasons.append("unadvertised_property")
        return reasons

    # ---- reporting ----

    def summary(self) -> dict:
        return {
            "probed": len(self._probed),
            "remaining": len(self._queue),
            "responded": len(self.responses),
            "findings": len(self.findings),
        }
