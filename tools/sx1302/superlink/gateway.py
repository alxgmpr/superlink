"""
SuperLink standalone gateway.

Implements the connection state machine for pairing with
factory-default sensors via Curve25519 DH exchange.
"""

import argparse
import csv
import logging
import sys
import time
from datetime import datetime, timezone

from .adopt import DEFAULT_NETWORK_ID
from .decoder import format_mac, parse_frame, SuperLinkFrame
from .bridge.core import BridgeCore, OutgoingFrame
from .bridge.observers import SweepObserver
from .bridge.profiles import ProfileRegistry
from .bridge.session import DeviceSession, State
from .bridge.store import JsonDeviceStore

# Factory-default LoRa pairing key (docs/protocol/crypto_and_pairing.md).
PAIRING_KEY = bytes.fromhex(
    "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
)

log = logging.getLogger(__name__)


class GatewaySession(DeviceSession):
    """Backward-compat adapter over DeviceSession.

    Preserves the legacy single-session surface that `tests/test_gateway.py`
    and `tests/test_gateway_sweep.py` (and the standalone `main()` runtime)
    drive:
      - constructor `GatewaySession(gw_mac=..., pairing_key=...)` (no record),
      - `handle_rx(raw, ul_channel) -> (frame, tx_data, tx_freq_hz)`,
      - `.state` as the `State` enum (readable AND settable),
      - the RE PROPERTY/message sweep (`sweep`, `_next_probe_body`,
        `_ingest_app_report`) and the adopt-key persistence/reconnect helpers.

    All protocol logic lives in `DeviceSession`; the sweep is re-attached here
    via the `_observe` / `_command_window` / `_sustain` / `_on_commit` hooks so
    no protocol logic is duplicated.
    """

    # Where committed addDevice keys are cached so the gateway can rejoin an
    # already-adopted sensor after a restart (no factory-reset needed).
    KEYFILE = "/tmp/superlink_adopt.json"

    def __init__(self, gw_mac: bytes, pairing_key: bytes,
                 beacon_interval: float = 240.0,
                 kdf_context: bytes | None = None,
                 mgmt_counter_start: int = 0x7c,
                 network_id: int = DEFAULT_NETWORK_ID,
                 sweep=None):
        super().__init__(
            None, gw_mac, pairing_key, profiles=None,
            beacon_interval=beacon_interval, kdf_context=kdf_context,
            mgmt_counter_start=mgmt_counter_start, network_id=network_id)
        # Optional PROPERTY_REQUEST / message-id memory-disclosure sweep. When
        # set, the gateway probes the adopted sensor on its RX windows.
        self.sweep = sweep
        self._sweep_tag = 0

    # --- legacy `state` surface: the raw State enum, readable and settable ---
    @property
    def state(self) -> State:
        return self._state

    @state.setter
    def state(self, value: State) -> None:
        self._state = value

    # --- legacy RX entry point: raw bytes in, (frame, tx_data, tx_freq) out ---
    def handle_rx(self, raw: bytes, ul_channel: int = 0
                  ) -> tuple[SuperLinkFrame | None, bytes | None, int]:
        """Process a received raw frame based on current state.

        Returns (frame, tx_data, tx_freq_hz): the decoded frame (or None), the
        raw bytes to transmit (or None), and the TX frequency in Hz (or 0).
        """
        frame = parse_frame(raw)
        if frame is None:
            return None, None, 0
        decoded, frames, _events = self._dispatch(frame, ul_channel, now=0.0)
        if frames:
            out = frames[0]
            return decoded, out.data, out.freq_hz
        return decoded, None, 0

    # ------------------------------------------------------- sweep hooks (RE)
    def _observe(self, frame: SuperLinkFrame, channel: int) -> list:
        """Feed the decrypted app report into the sweep, plus typed events."""
        if self.sweep is not None and self._adopted and frame.payload:
            self._ingest_app_report(frame.payload)
        return super()._observe(frame, channel)

    def _command_window(self, frame: SuperLinkFrame, channel: int):
        """0x53 command window: drive the sweep, else drain queued bodies."""
        if self.sweep is None:
            return super()._command_window(frame, channel)
        body = self._next_probe_body()
        # Sustain the command window: with no queued probe but the sweep still
        # working (e.g. OtaPush awaiting a FIRMWARE_CHUNK_REQUEST), send a PING
        # keep-alive so the sensor keeps its command window open.
        keepalive = False
        if body is None and not self.sweep.done():
            from . import appmsg
            self._sweep_tag = (self._sweep_tag + 1) & 0xFF
            body = appmsg.encode_ping_request(tag=self._sweep_tag)
            keepalive = True
        if body is None:
            if self.sweep.done():
                log.info("SWEEP complete: %s", self.sweep.summary())
            return None
        from .hal import DL_FREQ_HZ
        dl_freq = DL_FREQ_HZ[channel - 1]
        tx = self._build_command(frame.mac, body, frame.seq_hi)
        log.info("SWEEP %s (reply to 0x53) -> %s seq=%02X.81 ctr=0 body=%s "
                 "on %.1f MHz", "keepalive" if keepalive else "cmd",
                 format_mac(frame.mac), frame.seq_hi, body.hex(), dl_freq / 1e6)
        return OutgoingFrame(data=tx, freq_hz=dl_freq, channel=channel)

    def _sustain(self, frame: SuperLinkFrame, channel: int):
        """0x44/0x54 sustained sweep exchange (ingest already done in _observe)."""
        if self.sweep is None or not self._adopted or not frame.payload:
            return None
        mid = frame.payload[0]
        if 1 <= channel <= 8:
            from .hal import DL_FREQ_HZ
            dl_freq = DL_FREQ_HZ[channel - 1]
            # (1) Sustained exchange: a solicited report arrives on 0x44
            # (DEVICE_INFO_REPORT 0x0a / PROPERTY_REPORT 0x0c). Send next probe.
            if frame.dctrl == 0x44 and (
                    mid in (0x0a, 0x0c)
                    or getattr(self.sweep, "sustain_on_any", False)):
                body = self._next_probe_body()
                if body is None and not self.sweep.done():
                    from . import appmsg
                    self._sweep_tag = (self._sweep_tag + 1) & 0xFF
                    body = appmsg.encode_ping_request(tag=self._sweep_tag)
                if body is not None:
                    tx = self._build_command(frame.mac, body, frame.seq_hi + 1)
                    log.info("SWEEP cmd (sustain <-0x44 seq=%02X) body=%s "
                             "on %.1f MHz", frame.seq_hi, body.hex(),
                             dl_freq / 1e6)
                    return OutgoingFrame(data=tx, freq_hz=dl_freq,
                                         channel=channel)
            # (2) PING keep-alive: on plain 0x54 telemetry, nudge the sensor
            # with a PING_REQUEST to try to hold the command session open.
            if (frame.dctrl == 0x54 and mid == 0x0c
                    and not self.sweep.done()):
                from . import appmsg
                self._sweep_tag = (self._sweep_tag + 1) & 0xFF
                body = appmsg.encode_ping_request(tag=self._sweep_tag)
                tx = self._build_command(frame.mac, body, frame.seq_hi + 1)
                log.info("SWEEP ping keep-alive (<-0x54 seq=%02X) on "
                         "%.1f MHz", frame.seq_hi, dl_freq / 1e6)
                return OutgoingFrame(data=tx, freq_hz=dl_freq, channel=channel)
        if self.sweep.done():
            log.info("SWEEP complete: %s", self.sweep.summary())
        return None

    def _on_commit(self) -> None:
        """Persist committed addDevice keys so --reconnect can reuse them."""
        self._persist_adopt_keys()

    def _next_probe_body(self) -> bytes | None:
        """Next application-layer probe body, or None if no sweep / exhausted.

        Order: one DEVICE_INFO_REQUEST first (to map the surface and learn the
        property value-size map), then PROPERTY_REQUEST batches until the id
        queue drains.
        """
        if self.sweep is None:
            return None
        from . import appmsg
        self._sweep_tag = (self._sweep_tag + 1) & 0xFF
        # MessageSweep / PingProbe drive themselves via next_probe(tag).
        if hasattr(self.sweep, "next_probe"):
            return self.sweep.next_probe(self._sweep_tag)
        # PropertySweep: DEVICE_INFO_REQUEST first (maps the surface + value-size
        # map), then PROPERTY_REQUEST batches until the id queue drains.
        if self.sweep.device_info is None:
            return appmsg.encode_device_info_request(tag=self._sweep_tag)
        batch = self.sweep.next_batch()
        if not batch:
            return None
        return appmsg.encode_property_request(batch, tag=self._sweep_tag)

    def _ingest_app_report(self, payload: bytes) -> None:
        """Route a decrypted UL app message into the sweep controller."""
        if self.sweep is None or not payload or len(payload) < 2:
            return
        from . import appmsg
        # MessageSweep / PingProbe ingest the raw app message (matched by tag)
        # and log any interesting response themselves.
        if hasattr(self.sweep, "next_probe"):
            n_before = len(self.sweep.findings)
            self.sweep.ingest(payload)
            log.info("SWEEP resp msgId=0x%02x tag=0x%02x body=%s",
                     payload[0], payload[1], payload[2:].hex())
            for f in self.sweep.findings[n_before:]:
                log.warning("SWEEP FINDING %s", f)
            return
        msg_id = payload[0]
        if msg_id == appmsg.MessageId.DEVICE_INFO_REPORT:
            try:
                report = appmsg.decode_message(payload)
            except ValueError as exc:
                log.warning("bad DEVICE_INFO_REPORT: %s", exc)
                return
            self.sweep.set_device_info(report)
            log.info("SWEEP device_info: type=0x%04x fw=%s hw=%d "
                     "anonId=%s supportedMsgs=%s supportedProps=%s",
                     report["deviceType"], report["fwVersion"],
                     report["hardwareRevision"],
                     report["anonymousDeviceId"].hex(),
                     report["supportedMessageIds"],
                     [p["propertyId"] for p in report["supportedProperties"]])
        elif msg_id == appmsg.MessageId.PROPERTY_REPORT:
            try:
                report = appmsg.decode_message(payload, sizes=self.sweep.sizes)
            except ValueError as exc:
                log.warning("bad PROPERTY_REPORT: %s", exc)
                return
            n_before = len(self.sweep.findings)
            self.sweep.record_report(report)
            for f in self.sweep.findings[n_before:]:
                log.warning("SWEEP FINDING id=%d (%s) ch=%s value=%s reasons=%s",
                            f["propertyId"], f["name"], f["channel"],
                            f["value"].hex(), f["reasons"])

    def _persist_adopt_keys(self) -> None:
        """Save the committed addDevice keys so --reconnect can reuse them."""
        try:
            import json
            with open(self.KEYFILE, "w") as f:
                json.dump({
                    "mac": self.sensor_mac.hex() if self.sensor_mac else None,
                    "primary": self._derived_addDevice_key.hex(),
                    "fallback": self._derived_addDevice_fb_key.hex(),
                }, f)
            log.info("persisted addDevice keys to %s", self.KEYFILE)
        except Exception as exc:  # non-fatal
            log.warning("could not persist adopt keys: %s", exc)

    def load_adopt_keys(self) -> bool:
        """Enter the adopted/reconnect state from cached keys (KDF ctx=primary,
        transport=fallbackKey). Returns True if keys were loaded. Lets the
        gateway rejoin an already-adopted sensor without a fresh adoption."""
        try:
            import json
            with open(self.KEYFILE) as f:
                d = json.load(f)
            self._derived_addDevice_key = bytes.fromhex(d["primary"])
            self._derived_addDevice_fb_key = bytes.fromhex(d["fallback"])
            self._kdf_context = self._derived_addDevice_key
            self._transport_key = self._derived_addDevice_fb_key
            self._adopted = True
            if d.get("mac"):
                self.sensor_mac = bytes.fromhex(d["mac"])
            log.info("RECONNECT: loaded addDevice keys (primary=%s "
                     "fallback=%s) — will rejoin adopted sensor",
                     self._derived_addDevice_key[:8].hex(),
                     self._derived_addDevice_fb_key[:8].hex())
            return True
        except FileNotFoundError:
            log.warning("--reconnect: no cached keys at %s (need one fresh "
                        "adoption first)", self.KEYFILE)
            return False
        except Exception as exc:
            log.warning("--reconnect: could not load keys: %s", exc)
            return False


def parse_gw_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse gateway CLI arguments."""
    parser = argparse.ArgumentParser(
        description="SuperLink standalone gateway"
    )
    parser.add_argument(
        "--mac", required=True, metavar="MAC",
        help="Gateway MAC to advertise (e.g. AA:BB:CC:DD:EE:FF)",
    )
    parser.add_argument(
        "--beacon-interval", type=float, default=240, metavar="SEC",
        help="Seconds between beacon TX (default: 240)",
    )
    parser.add_argument(
        "--log", metavar="FILE.csv",
        help="Log all RX/TX frames to CSV file",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print raw hex and crypto details",
    )
    parser.add_argument(
        "--tx-delay", type=int, default=1_000_000, metavar="US",
        help="TX delay in microseconds after RX timestamp (default 1000000=1s, "
             "matches real Ubi gateway measured at 1.008s sensor UL→GW DL). "
             "Sensor's post-discovery RX window opens ~1s after its TX end.",
    )
    parser.add_argument(
        "--invert-iq", action="store_true",
        help="Invert IQ polarization for DL TX (LoRaWAN convention)",
    )
    parser.add_argument(
        "--kdf-context", metavar="HEX",
        help="32-byte hex value to use as keypair+0x30 in the session-key KDF "
             "(default: pairing_key). Captured real-bridge values to try: "
             "c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db",
    )
    parser.add_argument(
        "--mgmt-counter-start", type=lambda x: int(x, 0), default=0x7c,
        metavar="N",
        help="Initial value for the DL-management sequence counter (position 1 "
             "of 0x53/0x44/0x43 reply bodies). Default 0x7c matches pair4 "
             "real-bridge capture. Increments by 1 per reply.",
    )
    parser.add_argument(
        "--sweep", nargs="?", const="undefined", metavar="IDS",
        help="Enable PROPERTY_REQUEST memory-disclosure sweep of the adopted "
             "sensor. Optional IDS selects which property ids to probe: "
             "'undefined' (default — 0,18,43-255, the payoff set), 'all' "
             "(0-255), or an explicit list like '0,18,43-64'. Probes are sent "
             "on 0x54 data-frame RX windows; adoption is untouched.",
    )
    parser.add_argument(
        "--sweep-batch", type=int, default=8, metavar="N",
        help="Property ids per PROPERTY_REQUEST probe (default 8).",
    )
    parser.add_argument(
        "--msg-sweep", nargs="?", const="undefined", metavar="IDS",
        help="Enable MESSAGE-ID sweep: send each message id as [id][tag] and "
             "record the response. IDS: 'undefined' (default — 0x00,0x0d,"
             "0x12-0xff, skipping reboot/reset/adopt), 'all', or an explicit "
             "list. Mutually exclusive with --sweep.",
    )
    parser.add_argument(
        "--ping-probe", action="store_true",
        help="Enable PING over-read probe: PING_REQUEST with varying data "
             "lengths, flag any PING_RESPONSE longer than sent (Heartbleed).",
    )
    parser.add_argument(
        "--fuzz", action="store_true",
        help="Enable the crafted-frame FUZZ harness: sends malformed app "
             "messages (length-field over-reads, oversized values, undefined "
             "opcodes) and flags anomalous responses. AGGRESSIVE — can crash "
             "the sensor. Pairs with SWD observation of the parser.",
    )
    parser.add_argument(
        "--reconnect", action="store_true",
        help="Rejoin an already-adopted sensor using addDevice keys cached from "
             "a prior commit (/tmp/superlink_adopt.json) — no factory-reset "
             "needed after a gateway restart.",
    )
    parser.add_argument(
        "--keep-awake", action="store_true",
        help="Hold the sensor awake with a continuous PING loop so a plain SWD "
             "attach lands on the running app (live keys resident). Pair with "
             "--reconnect.",
    )
    parser.add_argument(
        "--write-fuzz", action="store_true",
        help="WRITE-path fuzz corpus (Vector 1 OOB channel-index + Vector 3 "
             "multi-entry PROPERTY_SET desync). AGGRESSIVE writes — pair with "
             "the SWD crash oracle (tools/sensor_swd/crash_oracle.sh).",
    )
    parser.add_argument(
        "--ota-push", metavar="FILE",
        help="Push a firmware .ota to the sensor (controller-side relay). Sends "
             "FIRMWARE_UPDATE_START then serves the sensor's chunk requests from "
             "FILE. Use for firmware-capture-during-decrypt (SWD-dump mid-run).",
    )
    parser.add_argument(
        "--ota-evil-offset", type=lambda x: int(x, 0), metavar="OFF",
        help="Vector 2 OOB-write probe: enter OTA mode (UPDATE_START) then inject "
             "a FIRMWARE_CHUNK_RESPONSE at this attacker-chosen offset with a "
             "DEADBEEF marker. SWD-diff SRAM to find where it landed.",
    )
    parser.add_argument(
        "--ota-size", type=lambda x: int(x, 0), default=96270, metavar="N",
        help="Total firmware size to advertise in UPDATE_START for "
             "--ota-evil-offset (default 96270 = usl-motion .ota).",
    )
    parser.add_argument(
        "--ota-marker-len", type=int, default=64, metavar="N",
        help="Marker chunk length for --ota-evil-offset (default 64).",
    )
    parser.add_argument(
        "--ota-pause-at", type=lambda x: int(x, 0), default=None, metavar="OFF",
        help="With --ota-push, stall the transfer once the sensor requests an "
             "offset >= OFF, holding a known transfer state for an SWD dump.",
    )
    return parser.parse_args(argv)


def main():
    args = parse_gw_args()

    # Parse MAC
    try:
        gw_mac = bytes.fromhex(args.mac.replace(":", "").replace("-", ""))
        if len(gw_mac) != 6:
            raise ValueError("MAC must be 6 bytes")
    except ValueError as e:
        print(f"Error: invalid --mac: {e}", file=sys.stderr)
        sys.exit(1)

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    from .hal import SX1302, BW_500KHZ

    kdf_context = None
    if args.kdf_context:
        kdf_context = bytes.fromhex(args.kdf_context)
        if len(kdf_context) != 32:
            print(f"Error: --kdf-context must be 32 bytes (got {len(kdf_context)})",
                  file=sys.stderr)
            sys.exit(1)

    sweep = None
    if args.ota_push:
        from .sweep import OtaPush
        try:
            ota_bytes = open(args.ota_push, "rb").read()
        except OSError as e:
            print(f"Error: cannot read --ota-push file: {e}", file=sys.stderr)
            sys.exit(1)
        sweep = OtaPush(ota_bytes=ota_bytes, pause_at=args.ota_pause_at)
        log.info("OTA-PUSH relay: %s (%d bytes)%s — will drive the sensor's "
                 "firmware update; hammer SWD dumps during transfer",
                 args.ota_push, len(ota_bytes),
                 f", pause_at=0x{args.ota_pause_at:x}"
                 if args.ota_pause_at is not None else "")
    elif args.ota_evil_offset is not None:
        from .sweep import OtaPush
        sweep = OtaPush(total_size=args.ota_size,
                        evil_offset=args.ota_evil_offset,
                        evil_len=args.ota_marker_len)
        log.info("OTA-EVIL Vector-2: enter OTA mode (size=%d) then inject marker "
                 "chunk at offset 0x%x (len %d). SWD-diff to locate the write.",
                 args.ota_size, args.ota_evil_offset, args.ota_marker_len)
    elif args.write_fuzz:
        from .sweep import FuzzHarness, build_write_corpus
        sweep = FuzzHarness(build_write_corpus())
        log.info("WRITE-FUZZ enabled: %d write vectors (chan-index + desync) — "
                 "AGGRESSIVE, pair with SWD crash oracle", len(sweep._queue))
    elif args.keep_awake:
        from .sweep import KeepAwake
        sweep = KeepAwake()
        log.info("KEEP-AWAKE mode: continuous PING loop to hold the sensor "
                 "awake for SWD attach")
    elif args.msg_sweep:
        from .sweep import MessageSweep, parse_msg_id_spec
        try:
            ids = parse_msg_id_spec(args.msg_sweep)
        except ValueError as e:
            print(f"Error: invalid --msg-sweep IDS: {e}", file=sys.stderr)
            sys.exit(1)
        sweep = MessageSweep(ids=ids)
        log.info("MESSAGE-ID sweep enabled: %d ids (%s)", len(ids),
                 ",".join(f"0x{i:02x}" for i in ids[:12])
                 + (",…" if len(ids) > 12 else ""))
    elif args.ping_probe:
        from .sweep import PingProbe
        sweep = PingProbe()
        log.info("PING over-read probe enabled: lengths %s", sweep._queue)
    elif args.fuzz:
        from .sweep import FuzzHarness
        sweep = FuzzHarness()
        log.info("FUZZ harness enabled: %d crafted cases (AGGRESSIVE)",
                 len(sweep._queue))
    elif args.sweep:
        from .sweep import PropertySweep, parse_id_spec
        try:
            ids = parse_id_spec(args.sweep)
        except ValueError as e:
            print(f"Error: invalid --sweep IDS: {e}", file=sys.stderr)
            sys.exit(1)
        sweep = PropertySweep(ids=ids, batch_size=args.sweep_batch)
        log.info("PROPERTY_REQUEST sweep enabled: %d ids, batch=%d",
                 len(ids), args.sweep_batch)

    # --- Bridge core substrate (multi-device registry + persistence) --------
    # The pure BridgeCore engine (bridge/core.py) is the runtime's migration
    # target: a ProfileRegistry (data-driven property decode), a persistent
    # DeviceStore, a DeviceSession factory, and the orchestrator itself. When an
    # RE sweep is configured, the SweepObserver is subscribed to the core's typed
    # event stream so decoded DEVICE_INFO/PROPERTY reports flow into the sweep
    # controller through the public API instead of the private ingest hook.
    #
    # NOTE ON THE SPLIT (why the RX loop below still drives GatewaySession):
    # The RF-critical path — beaconing, the Curve25519 adoption handshake, the
    # post-rotation burst TX (`_pending_tx_frames`), --reconnect key reload, and
    # the sweep's *probe-send* sequencing on the sensor's 0x53/0x44/0x54 command
    # windows — lives in GatewaySession's command-window hooks and cannot be
    # reproduced by the observer (which only ingests reports) without changing
    # wire behavior. Those changes are unverifiable without the Pi/SX1302 + a
    # live sensor, so GatewaySession remains the driver here; the core+observer
    # are wired per the refactor spec and exercised by tests/test_bridge_observer.
    profiles = ProfileRegistry.load()
    store = JsonDeviceStore("/tmp/superlink_devices.json")

    def _session_factory(record):
        return DeviceSession(
            record, gw_mac, PAIRING_KEY, profiles=profiles,
            beacon_interval=args.beacon_interval, kdf_context=kdf_context,
            mgmt_counter_start=args.mgmt_counter_start)

    core = BridgeCore(store, profiles, _session_factory, auto_adopt=False)
    if sweep is not None:
        core.subscribe(SweepObserver(core, sweep).on_event)

    session = GatewaySession(
        gw_mac=gw_mac,
        pairing_key=PAIRING_KEY,
        beacon_interval=args.beacon_interval,
        kdf_context=kdf_context,
        mgmt_counter_start=args.mgmt_counter_start,
        sweep=sweep,
    )

    # CSV logging
    csv_file = None
    csv_writer = None
    if args.log:
        csv_file = open(args.log, "a", newline="")
        csv_writer = csv.writer(csv_file)
        if csv_file.tell() == 0:
            csv_writer.writerow([
                "timestamp", "direction", "state", "mac", "seq",
                "dctrl", "size", "payload", "interpretation",
            ])

    hal = None
    try:
        hal = SX1302()
        log.info("Starting SX1302 concentrator...")
        hal.start()
        log.info("Concentrator started (HAL %s)", hal.version())

        session.start()
        if args.reconnect:
            session.load_adopt_keys()
        log.info("Gateway MAC: %s — listening on UL channels", format_mac(gw_mac))

        while True:
            # No beacon needed — sensor discovers by sending 0x40 on UL channels

            # Poll for RX packets
            for pkt in hal.receive():
                if not pkt.crc_ok:
                    continue
                t_rx = time.monotonic()
                frame, tx_data, tx_freq = session.handle_rx(
                    pkt.payload, ul_channel=pkt.ul_channel)

                # Send DL response if requested
                if tx_data and tx_freq:
                    tx_ts = 0
                    if args.tx_delay:
                        tx_ts = pkt.timestamp_us + args.tx_delay
                    t_pre_tx = time.monotonic()
                    try:
                        hal.send(tx_freq, tx_data, bandwidth=BW_500KHZ,
                                 tx_timestamp_us=tx_ts,
                                 invert_pol=args.invert_iq)
                    except (ValueError, RuntimeError) as exc:
                        # A crafted/fuzz frame can exceed the PHY/concentrator TX
                        # limit (ValueError >256B, or lgw_send rc=-1 RuntimeError
                        # near the edge) — skip it rather than killing the
                        # gateway mid-sweep.
                        log.warning("TX skipped (%d bytes): %s",
                                    len(tx_data), exc)
                        continue
                    t_post_tx = time.monotonic()
                    mode = f"scheduled +{args.tx_delay}us" if tx_ts else "immediate"
                    log.info("TX %s: process=%.1fms send=%.1fms",
                             mode, (t_pre_tx - t_rx) * 1000,
                             (t_post_tx - t_pre_tx) * 1000)

                # Drain any TX frames the handler queued
                # (post-rotation burst after ADOPT_RESPONSE). The sensor
                # validates NN order strictly, so this MUST go on-air in
                # order — schedule ALL frames with sequential timestamps,
                # never mixing scheduled + immediate.
                pending = getattr(session, "_pending_tx_frames", None)
                if pending:
                    session._pending_tx_frames = []
                    base_ts = pkt.timestamp_us + (args.tx_delay or 1_000_000)
                    BURST_SPACING_US = 500_000  # 500ms — generous, safe
                    for i, (follow_tx, follow_freq) in enumerate(pending):
                        ts = base_ts + i * BURST_SPACING_US
                        hal.send(follow_freq, follow_tx,
                                 bandwidth=BW_500KHZ,
                                 tx_timestamp_us=ts,
                                 invert_pol=args.invert_iq)
                        log.info(
                            "burst TX %d/%d (scheduled t+%.1fs)",
                            i + 1, len(pending),
                            (ts - pkt.timestamp_us) / 1e6)

                if frame and csv_writer:
                    csv_writer.writerow([
                        datetime.now(timezone.utc).isoformat(),
                        frame.direction,
                        session.state.value,
                        format_mac(frame.mac),
                        f"{frame.seq_hi:02X}.{frame.seq_lo:02X}",
                        f"{frame.dctrl:02X}",
                        len(pkt.payload),
                        frame.payload.hex() if frame.payload else "",
                        frame.interpretation or "",
                    ])
                    csv_file.flush()

            time.sleep(0.01)

    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        if hal:
            hal.stop()
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    main()
