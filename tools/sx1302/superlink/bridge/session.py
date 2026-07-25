"""
DeviceSession: single-sensor SuperLink state machine (pure, no I/O).

Extracted verbatim (behavior-preserving) from gateway.GatewaySession. This is
the single authoritative home of the connection/pairing protocol logic. The
legacy `gateway.GatewaySession` is now a thin backward-compat adapter over this
class.

New surface (BridgeCore / SessionProtocol):
  - feed(frame, channel, now)  -> (list[OutgoingFrame], list[Event])
  - tick(now)                  -> (list[OutgoingFrame], list[Event])
  - queue_body(body)
  - state: str
  - to_record() -> DeviceRecord

RE-only members (sweep, _sweep_tag, _ingest_app_report, _next_probe_body) do
NOT live here — they remain in the GatewaySession adapter. Where the sweep was
fed a decrypted app report, this class instead builds typed events via
`events_from_app_message` (returned in the event list). Queued action bodies
(`queue_body`) go out on the next 0x53 command window via `_build_command`.
"""

import enum
import logging
import secrets
import time

from ..adopt import (
    DEFAULT_NETWORK_ID,
    MSG_ADOPT_RESPONSE,
    decode_adopt_response,
    encode_adopt_request,
    kdf_E,
)
from ..crypto import generate_keypair, compute_shared_secret, derive_session_key
from ..decoder import (
    build_frame, build_nonce, compute_mic, decrypt_frame,
    format_mac, parse_frame, SuperLinkFrame,
)
from .core import OutgoingFrame
from .mapping import events_from_app_message
from .store import DeviceRecord

try:
    import pysodium
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

log = logging.getLogger(__name__)


# Global default adoption key. v2 sensor firmware seeds the initial-pairing
# session-key KDF (keypair+0x30 context) with THIS key, not the pairing key
# (v1 firmware used the pairing key). Everything else in derive_session_key is
# unchanged: blake2b32(shared || gw_pub || sensor_pub || context).
LORA_DEVICE_DEFAULT_ADOPTION_KEY = bytes.fromhex(
    "c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db"
)


def is_discovery_ad(payload: bytes | None) -> bool:
    """True if a decrypted 0x40 payload is a SuperLink discovery advertisement.

    v1 firmware: ``01 ae94 NN 00000000``        (8 bytes)
    v2 firmware: ``02 ae94 NN 00000000 0002``   (10 bytes)

    The ``ae94`` marker at [1:3] is the stable discriminator across firmware
    versions; the leading byte is the protocol version (1 or 2). Gating on the
    marker (not the version byte) is what lets the gateway hear v2 sensors.
    """
    return (payload is not None and len(payload) >= 8
            and payload[1:3] == b"\xae\x94"
            and payload[0] in (0x01, 0x02))


def initial_pairing_kdf_context(payload: bytes, pairing_key: bytes) -> bytes:
    """Session-KDF context for a fresh (unadopted) pairing, by firmware version.

    v2 (payload[0] == 0x02) uses the global default adoption key; v1 uses the
    pairing key. Only for the initial handshake — a post-commit reconnect uses
    the rotated addDevice.key instead.
    """
    if payload and payload[0] == 0x02:
        return LORA_DEVICE_DEFAULT_ADOPTION_KEY
    return pairing_key


class State(enum.Enum):
    IDLE = "idle"
    BEACONING = "beaconing"
    WAIT_CONNREQ = "wait_connreq"
    DH_EXCHANGE = "dh_exchange"
    CHALLENGE = "challenge"
    SETUP = "setup"
    ACTIVE = "active"


# Internal State enum -> DEVICE_STATES vocabulary (new surface `state: str`).
_ADOPTING_STATES = (State.BEACONING, State.WAIT_CONNREQ, State.DH_EXCHANGE,
                    State.CHALLENGE, State.SETUP)


class DeviceSession:
    """Manages a single sensor connection lifecycle (pure state machine)."""

    def __init__(self, record: DeviceRecord | None, gw_mac: bytes,
                 pairing_key: bytes, profiles=None,
                 beacon_interval: float = 240.0,
                 kdf_context: bytes | None = None,
                 mgmt_counter_start: int = 0x7c,
                 network_id: int = DEFAULT_NETWORK_ID,
                 now: float = 0.0):
        self.gw_mac = gw_mac
        self.pairing_key = pairing_key
        self.profiles = profiles
        self.beacon_interval = beacon_interval
        self.mgmt_counter_start = mgmt_counter_start
        # Console networkId (4-byte BE trailer in ADOPT_REQUEST). Per-console;
        # any 32-bit value works as long as the same one is used for the life
        # of this session against this sensor.
        self.network_id = network_id

        self._state = State.IDLE
        self.session_key: bytes | None = None

        # Queued application-layer bodies to transmit on the next DL window
        # (drained via _build_command on the sensor's 0x53 command poll).
        self._pending_bodies: list[bytes] = []
        # Property value-size map + known device type used to decode app
        # messages into typed events. Populated as we learn them.
        self._prop_sizes: dict | None = None

        # DH state (LoRa-side, between us and the sensor)
        self._privkey: bytes | None = None
        self._pubkey: bytes | None = None
        self._remote_pubkey: bytes | None = None

        # Application-layer ADOPT_REQUEST ephemeral privates. Set when we send
        # the 70B ADOPT_REQUEST as the 0x74 reply; consumed when the sensor's
        # ADOPT_RESPONSE comes back. Discarded after one round-trip.
        self._eph_priv_r: bytes | None = None
        self._eph_priv_o: bytes | None = None

        # Sequence counters
        self._tx_seq_hi = 0
        self._tx_seq_lo = 0
        self._ul_counter_offset = 0

        # Timing (now-clock for the new surface; monotonic for the legacy
        # beacon_due()/build_beacon() adapter path — a given instance is driven
        # by exactly one surface so the shared field never mixes clocks).
        self._last_beacon_time = 0.0

        # Adoption bookkeeping.
        # _adopted: set once we OBSERVE the sensor commit (adopted-form 0x40
        #   discovery `01ae94 8N 0000048f`); thereafter the KDF context is the
        #   primary addDevice.key and the handshake transport key is fallbackKey.
        # _adopt_pending: after the ADOPT round-trip produced (primary, fallback)
        #   keys but BEFORE the sensor committed — we do NOT rotate yet.
        # _kdf_context: keypair+0x30 context fed into the session-key KDF.
        # _transport_key: outer XSalsa20 key for the 0x62/0x42 connect handshake.
        # _derived_addDevice_{key,fb_key}: persistent keys derived from ADOPT.
        if record is not None:
            self.sensor_mac: bytes | None = record.mac if record.mac else None
            self._device_type = record.device_type
            self._derived_addDevice_key = record.primary_key
            self._derived_addDevice_fb_key = record.fallback_key
            self._kdf_context = (
                record.kdf_context if record.kdf_context is not None
                else (kdf_context if kdf_context is not None else pairing_key))
            # A persisted (adopted) or operator-supplied context is locked in;
            # only an unset default gets version-selected at discovery time.
            self._kdf_context_explicit = (
                record.kdf_context is not None or kdf_context is not None)
            self._transport_key = (
                record.transport_key if record.transport_key is not None
                else pairing_key)
            self._adopted = record.adopted
            self._tx_seq_hi = record.tx_seq_hi
            self._tx_seq_lo = record.tx_seq_lo
            self._ul_counter_offset = record.ul_counter_offset
        else:
            self.sensor_mac = None
            self._device_type = None
            self._derived_addDevice_key = None
            self._derived_addDevice_fb_key = None
            self._kdf_context = (
                kdf_context if kdf_context is not None else pairing_key)
            self._kdf_context_explicit = kdf_context is not None
            self._transport_key = pairing_key
            self._adopted = False

        self._adopt_pending = False

    # ------------------------------------------------------------------ state
    @property
    def state(self) -> str:
        """New-surface state as a DEVICE_STATES string."""
        if self._adopted:
            return "adopted"
        if self._state == State.ACTIVE:
            return "active"
        if self._state in _ADOPTING_STATES:
            return "adopting"
        return self._state.value

    @property
    def mac(self) -> bytes | None:
        return self.sensor_mac

    # ------------------------------------------------------------- lifecycle
    def start(self, now: float = 0.0):
        """Transition from IDLE to BEACONING."""
        self._privkey, self._pubkey = generate_keypair()
        self._state = State.BEACONING
        if hasattr(self, "_mgmt_counter"):
            del self._mgmt_counter
        self._last_beacon_time = now
        log.info("Session started, entering BEACONING state")

    def beacon_due(self) -> bool:
        """Check if it's time to send a beacon (legacy monotonic clock)."""
        if self._state != State.BEACONING:
            return False
        return (time.monotonic() - self._last_beacon_time) >= self.beacon_interval

    def _beacon_header(self) -> bytes:
        mctrl = 0x00
        dctrl = 0x00  # TBD — beacon dctrl value unknown
        seq_hi = self._tx_seq_hi & 0xFF
        seq_lo = self._tx_seq_lo & 0xFF
        return bytes([mctrl, dctrl]) + self.gw_mac + bytes([seq_hi, seq_lo])

    def build_beacon(self) -> bytes:
        """Build a plaintext beacon frame (legacy path, sets monotonic clock)."""
        header = self._beacon_header()
        self._last_beacon_time = time.monotonic()
        log.info("Built beacon frame (%d bytes)", len(header))
        return header

    # ------------------------------------------------------------ new surface
    def queue_body(self, body: bytes) -> None:
        """Queue an app-message body for the next DL command window."""
        self._pending_bodies.append(body)

    def feed(self, frame: SuperLinkFrame | None, channel: int, now: float
             ) -> tuple[list[OutgoingFrame], list]:
        """Process a parsed frame; return (outgoing frames, events)."""
        _decoded, frames, events = self._dispatch(frame, channel, now)
        return frames, events

    def tick(self, now: float) -> tuple[list[OutgoingFrame], list]:
        """Time-driven work (beacon emission)."""
        frames: list[OutgoingFrame] = []
        events: list = []
        if (self._state == State.BEACONING
                and (now - self._last_beacon_time) >= self.beacon_interval):
            from ..hal import BEACON_FREQ_HZ
            header = self._beacon_header()
            self._last_beacon_time = now
            frames.append(OutgoingFrame(data=header, freq_hz=BEACON_FREQ_HZ,
                                        channel=0))
            log.info("Emitted beacon on tick (%d bytes)", len(header))
        return frames, events

    def to_record(self) -> DeviceRecord:
        """Snapshot the session's persistent state into a DeviceRecord."""
        return DeviceRecord(
            mac=self.sensor_mac if self.sensor_mac else b"",
            device_type=self._device_type,
            primary_key=self._derived_addDevice_key,
            fallback_key=self._derived_addDevice_fb_key,
            kdf_context=self._kdf_context,
            transport_key=self._transport_key,
            adopted=self._adopted,
            tx_seq_hi=self._tx_seq_hi,
            tx_seq_lo=self._tx_seq_lo,
            ul_counter_offset=self._ul_counter_offset,
        )

    # -------------------------------------------------------------- dispatch
    def _dispatch(self, frame: SuperLinkFrame | None, channel: int, now: float
                  ) -> tuple[SuperLinkFrame | None, list[OutgoingFrame], list]:
        """Shared RX state-machine dispatch used by both surfaces.

        Returns (decoded_frame, outgoing_frames, events). The legacy adapter
        pulls the decoded frame + first outgoing frame back out; the new
        surface returns just (frames, events).
        """
        if frame is None:
            return None, [], []

        if self._state == State.ACTIVE:
            return self._handle_active(frame, channel)
        elif self._state == State.BEACONING:
            return self._handle_beaconing(frame, channel)

        log.debug("RX in %s state: dctrl=0x%02X from %s (no handler)",
                  self._state.value, frame.dctrl, format_mac(frame.mac))
        return None, [], []

    # --------------------------------------------------------- hooks (adapter)
    def _observe(self, frame: SuperLinkFrame, channel: int) -> list:
        """Turn a decrypted UL app message into typed events."""
        if not (self._adopted and frame.payload):
            return []
        try:
            events = events_from_app_message(
                frame.mac, frame.payload, self.profiles,
                sizes=self._prop_sizes, device_type=self._device_type)
        except Exception as exc:  # noqa: BLE001 - decode is best-effort
            log.debug("app-message decode failed: %s", exc)
            return []
        # Learn the device type from a DEVICE_INFO_REPORT so later decodes can
        # use device-specific property profiles.
        for ev in events:
            dtype = getattr(ev, "device_type", None)
            if dtype is not None:
                self._device_type = dtype
        return events

    def _next_dl_body(self) -> bytes | None:
        """Pop the next queued app-message body, or None."""
        if self._pending_bodies:
            return self._pending_bodies.pop(0)
        return None

    def _command_window(self, frame: SuperLinkFrame, channel: int
                        ) -> OutgoingFrame | None:
        """DL reply to the sensor's 0x53 command poll (drains queued bodies)."""
        body = self._next_dl_body()
        if body is None:
            return None
        from ..hal import DL_FREQ_HZ
        dl_freq = DL_FREQ_HZ[channel - 1]
        tx = self._build_command(frame.mac, body, frame.seq_hi)
        log.info("cmd (reply to 0x53) -> %s seq=%02X.81 ctr=0 body=%s on %.1f MHz",
                 format_mac(frame.mac), frame.seq_hi, body.hex(), dl_freq / 1e6)
        return OutgoingFrame(data=tx, freq_hz=dl_freq, channel=channel)

    def _sustain(self, frame: SuperLinkFrame, channel: int
                 ) -> OutgoingFrame | None:
        """Optional DL follow-up on 0x44/0x54 windows (base: none)."""
        return None

    def _on_commit(self) -> None:
        """Called when the sensor's adoption commit is observed (base: no-op)."""

    # ------------------------------------------------------------ ACTIVE state
    def _handle_active(self, frame: SuperLinkFrame, channel: int = 0
                       ) -> tuple[SuperLinkFrame | None, list[OutgoingFrame], list]:
        """Handle frames in ACTIVE state — decrypt UL, emit any DL response."""
        events: list = []
        if self.sensor_mac and frame.mac != self.sensor_mac:
            return None, [], []
        if self.session_key is None:
            return None, [], []
        if frame.dctrl not in (0x54, 0x44, 0x40, 0x53, 0x43):
            log.info("RX dctrl=0x%02X seq=%02X.%02X (ignored in ACTIVE)",
                     frame.dctrl, frame.seq_hi, frame.seq_lo)
            return None, [], []

        # 0x40 discovery: pairing_key + counter=0.
        # 0x53 / 0x43 post-pairing management: session_key + counter=0 (same
        #   zero-counter pattern as 0x40, confirmed from real-bridge capture
        #   NONCE=e053<mac><seq>00000000... with key=session_key).
        # 0x54 / 0x44 data: session_key + counter = seq_hi - ul_counter_offset.
        if frame.dctrl == 0x40:
            frame = decrypt_frame(frame, self.pairing_key,
                                  ul_counter_offset=frame.seq_hi)
        elif frame.dctrl in (0x53, 0x43):
            # Management frames use counter=0 during adoption, but the sensor's
            # mgmt-nonce counter ADVANCES once a command session is active (e.g.
            # after FIRMWARE_UPDATE_START). Hardcoding counter=0 makes every
            # post-UPDATE_START 0x53 decrypt to garbage. MIC-scan the counter
            # (cryptographically certain); clean frames still resolve to 0.
            scan_c = self._scan_data_counter(frame)
            if scan_c is not None:
                frame = decrypt_frame(frame, self.session_key,
                                      ul_counter_offset=frame.seq_hi - scan_c)
                log.debug("0x%02X counter=%d (seq=%02X.%02X)", frame.dctrl,
                          scan_c, frame.seq_hi, frame.seq_lo)
            else:
                frame = decrypt_frame(frame, self.session_key,
                                      ul_counter_offset=frame.seq_hi,
                                      dl_counter=0)
                log.info("0x%02X counter SCAN-FAIL seq=%02X.%02X (garbage?)",
                         frame.dctrl, frame.seq_hi, frame.seq_lo)
        else:
            # 0x54/0x44 data frames: the nonce counter lives in a separate
            # space from the handshake seq_hi. Find the counter whose plaintext
            # MIC verifies instead of the seq_hi-offset heuristic.
            scan_c = self._scan_data_counter(frame)
            if scan_c is not None:
                frame = decrypt_frame(frame, self.session_key,
                                      ul_counter_offset=frame.seq_hi - scan_c)
                log.info("data counter=%d (seq=%02X.%02X)",
                         scan_c, frame.seq_hi, frame.seq_lo)
            else:
                frame = decrypt_frame(frame, self.session_key,
                                      ul_counter_offset=self._ul_counter_offset)
                log.info("data counter SCAN-FAIL seq=%02X.%02X",
                         frame.seq_hi, frame.seq_lo)
        log.info("RX dctrl=0x%02X %s seq=%02X.%02X %s",
                 frame.dctrl, format_mac(frame.mac),
                 frame.seq_hi, frame.seq_lo,
                 frame.interpretation or
                 (frame.payload.hex() if frame.payload else "?"))

        # Application-layer ADOPT_RESPONSE body inspection. Sensor wraps the
        # 66-byte ADOPT_RESPONSE inside a 0x54 (data UL) frame after we send
        # the ADOPT_REQUEST. Body: [0x03] [tag] [32B devicePub] [32B deviceFbPub].
        # We feed the two pubkeys through kdf_E with the ephemeral privates we
        # stashed on TX to derive the new persistent (addDevice.key, fallbackKey),
        # then ACK with the real-bridge 0x63 commit ack.
        if (frame.payload and len(frame.payload) >= 66
                and frame.payload[0] == MSG_ADOPT_RESPONSE
                and 1 <= channel <= 8):
            try:
                tag, dev_pub, dev_fb_pub = decode_adopt_response(
                    frame.payload[:66])
            except ValueError as exc:
                log.warning("malformed ADOPT_RESPONSE body: %s", exc)
                return frame, [], events
            if not (self._eph_priv_r and self._eph_priv_o):
                log.warning(
                    "ADOPT_RESPONSE received but no ephemeral state "
                    "stored — did we send the ADOPT_REQUEST?")
                return frame, [], events

            self._derived_addDevice_key = kdf_E(self._eph_priv_r, dev_pub)
            self._derived_addDevice_fb_key = kdf_E(self._eph_priv_o, dev_fb_pub)
            log.info(
                "ADOPT_RESPONSE tag=0x%02x devicePub=%s devFbPub=%s",
                tag, dev_pub.hex(), dev_fb_pub.hex())
            log.info("  derived addDevice.key=%s",
                     self._derived_addDevice_key.hex())
            log.info("  derived addDevice.fallbackKey=%s",
                     self._derived_addDevice_fb_key.hex())
            # Discard the ephemerals — must NOT be reused.
            self._eph_priv_r = None
            self._eph_priv_o = None

            from ..hal import DL_FREQ_HZ
            dl_freq = DL_FREQ_HZ[channel - 1]
            # Commit ack: the real bridge answers ADOPT_RESPONSE with a single
            # 0x63 REQUEST_STATUS_RESPONSE(status=OK) body `01 00` (ground truth
            # bridge_adopt_fresh_pass2_20260722.log frame 44). The 0x63 ACK
            # ECHOES the acked frame's seq_hi and increments seq_lo by 1; the DL
            # nonce counter follows the seq_hi-1 offset seen across the ADOPT
            # region. Building it from our own independent counter leaves the
            # ACK uncorrelated, so the sensor reverts to unadopted.
            confirm_body = bytes([0x01, 0x00])
            ack_seq_hi = frame.seq_hi
            ack_seq_lo = (frame.seq_lo + 1) & 0xFF
            ack_ctr = (frame.seq_hi - 1) & 0xFF
            ack_header = (bytes([0xE0, 0x63]) + frame.mac
                          + bytes([ack_seq_hi, ack_seq_lo]))
            ack_mic = compute_mic(ack_header, confirm_body)
            tx_frame = build_frame(
                0xE0, 0x63, frame.mac, ack_seq_hi, ack_seq_lo,
                ack_mic, confirm_body, self.session_key, counter=ack_ctr)
            log.info("adoption commit-ack TX 0x63 seq=%02X.%02X ctr=%d on "
                     "%.1f MHz (body=%s)", ack_seq_hi, ack_seq_lo, ack_ctr,
                     dl_freq / 1e6, confirm_body.hex())

            # Do NOT rotate keys yet. The sensor has all it needs to derive its
            # own (primary, fallback) but has not committed. Drop to BEACONING
            # and wait to OBSERVE the commit before rotating. The keys stay
            # stashed; the swap happens in _handle_beaconing's 0x40 handler.
            self._adopt_pending = True
            self._privkey, self._pubkey = generate_keypair()
            self._state = State.BEACONING
            log.info("ADOPT round-trip done; stashed primary=%s fallback=%s; "
                     "awaiting adopted-form 0x40 (commit) before rotating",
                     self._derived_addDevice_key[:8].hex(),
                     self._derived_addDevice_fb_key[:8].hex())
            return frame, [OutgoingFrame(data=tx_frame, freq_hz=dl_freq,
                                         channel=channel)], events

        # Pre-commit: answer the sensor's first 0x53 mgmt poll with the
        # ADOPT_REQUEST directly (ground truth bridge_adopt_fresh_pass2). There
        # is NO pre-commit DEVICE_INFO_REQUEST / PROPERTY_REQUEST — those happen
        # only AFTER the sensor commits.
        if frame.dctrl == 0x53 and 1 <= channel <= 8 and not self._adopted:
            from ..hal import DL_FREQ_HZ
            dl_freq = DL_FREQ_HZ[channel - 1]
            if not _HAS_CRYPTO:
                raise RuntimeError(
                    "pysodium required for ADOPT_REQUEST keypair generation")
            if not hasattr(self, "_mgmt_counter"):
                self._mgmt_counter = getattr(self, "mgmt_counter_start", 0x7c)
            mgmt = self._mgmt_counter & 0xFF
            self._mgmt_counter += 1
            # Fresh ephemeral keypair, stashed so the ADOPT_RESPONSE handler
            # derives the rotated addDevice.key via kdf_E.
            self._eph_priv_r = secrets.token_bytes(32)
            self._eph_priv_o = secrets.token_bytes(32)
            gw_pub = pysodium.crypto_scalarmult_curve25519_base(
                self._eph_priv_r)
            gw_fb_pub = pysodium.crypto_scalarmult_curve25519_base(
                self._eph_priv_o)
            body = encode_adopt_request(
                mgmt, gw_pub, gw_fb_pub, self.network_id)
            tx_frame = self._build_dl_reply(frame.mac, body, dctrl=0x74)
            log.info("ADOPT_REQUEST (reply to 0x53) tag=0x%02x gw_pub=%s "
                     "gw_fb_pub=%s networkId=0x%x on %.1f MHz",
                     mgmt, gw_pub.hex(), gw_fb_pub.hex(), self.network_id,
                     dl_freq / 1e6)
            return frame, [OutgoingFrame(data=tx_frame, freq_hz=dl_freq,
                                         channel=channel)], events

        # Observe the decrypted app message as typed events (adopted only). This
        # is where the old code fed the RE sweep via _ingest_app_report.
        events += self._observe(frame, channel)

        # Post-adoption: the sensor's 0x53 mgmt poll is its COMMAND WINDOW — the
        # only point it listens for and acts on a request. Drain a queued body.
        if frame.dctrl == 0x53 and 1 <= channel <= 8 and self._adopted:
            of = self._command_window(frame, channel)
            return frame, ([of] if of is not None else []), events

        # Optional sustained DL follow-up (RE sweep, in the adapter).
        of = self._sustain(frame, channel)
        return frame, ([of] if of is not None else []), events

    # ------------------------------------------------------------- DL builders
    def _build_dl_reply(self, mac: bytes, body: bytes, dctrl: int = 0x74) -> bytes:
        """Build an encrypted DL frame carrying an app-message body.

        Continues the post-pairing seq/counter progression (shared DL-data
        counter) so consecutive DL frames stay in sequence for the sensor's
        nonce.
        """
        self._post_pair_tx_seq_hi = getattr(self, "_post_pair_tx_seq_hi", 0) + 1
        self._post_pair_tx_seq_lo = getattr(self, "_post_pair_tx_seq_lo", 0) + 1
        self._post_pair_counter = getattr(self, "_post_pair_counter", -1) + 1
        seq_hi = self._post_pair_tx_seq_hi & 0xFF
        seq_lo = self._post_pair_tx_seq_lo & 0xFF
        counter = self._post_pair_counter
        header = bytes([0xE0, dctrl]) + mac + bytes([seq_hi, seq_lo])
        mic = compute_mic(header, body)
        return build_frame(0xE0, dctrl, mac, seq_hi, seq_lo, mic, body,
                           self.session_key, counter=counter)

    def _build_0x74_reply(self, mac: bytes, body: bytes) -> bytes:
        """0x74 DL reply (sweep probes / mgmt replies)."""
        return self._build_dl_reply(mac, body, dctrl=0x74)

    def _build_command(self, mac: bytes, body: bytes, seq_hi: int,
                       seq_lo: int = 0x81, ctr: int = 0) -> bytes:
        """Build a DL 0x74 command frame in the sensor's command-window format
        (seq_lo 0x81, ctr 0) — the shape the sensor accepts for ADOPT_REQUEST
        and DEVICE_INFO_REQUEST."""
        seq_hi &= 0xFF
        header = bytes([0xE0, 0x74]) + mac + bytes([seq_hi, seq_lo])
        mic = compute_mic(header, body)
        return build_frame(0xE0, 0x74, mac, seq_hi, seq_lo, mic, body,
                           self.session_key, counter=ctr)

    def _scan_data_counter(self, frame) -> int | None:
        """Find the XSalsa20 nonce counter for a UL data frame by MIC match.

        The MIC is BLAKE2b-32 over header(10B) || 4 zero bytes || plaintext, so
        for each candidate counter we decrypt and check the recomputed MIC
        against the decrypted MIC. Returns the counter (0..63) or None.
        """
        if not _HAS_CRYPTO or not frame.encrypted or self.session_key is None:
            return None
        header = (bytes([frame.mctrl, frame.dctrl]) + frame.mac
                  + bytes([frame.seq_hi, frame.seq_lo]))
        ct = frame.encrypted
        for c in range(0, 64):
            nonce = build_nonce(frame.mctrl, frame.dctrl, frame.mac,
                                frame.seq_hi, frame.seq_lo, c)
            pt = pysodium.crypto_stream_xor(ct, len(ct), nonce, self.session_key)
            if compute_mic(header, pt[4:]) == pt[:4]:
                return c
        return None

    # --------------------------------------------------------- BEACONING state
    def _handle_beaconing(self, frame: SuperLinkFrame, channel: int = 0
                          ) -> tuple[SuperLinkFrame | None, list[OutgoingFrame], list]:
        """Handle frames in BEACONING state.

        Listens for:
        - 0x40 discovery ads: respond with 0x62 ConnectionRsp (DH pubkey)
        - 0x42 ConnectionChallenge: extract pubkey, do DH, derive session key
        """
        from ..hal import DL_FREQ_HZ, BW_500KHZ
        events: list = []

        if frame.dctrl == 0x40:
            # Discovery advertisement — decrypt with default pairing key,
            # counter=0: pass seq_hi as offset so seq_hi - offset = 0
            frame = decrypt_frame(frame, self.pairing_key,
                                  ul_counter_offset=frame.seq_hi)
            if is_discovery_ad(frame.payload):
                self.sensor_mac = frame.mac
                # Adopted-form discovery carries a non-zero networkId trailer
                # (`01ae94 8N 0000048f`); unadopted-form is `01ae94 NN 00000000`.
                # The non-zero networkId is the reliable discriminator.
                adopted_form = (len(frame.payload) >= 8
                                and frame.payload[4:8] != b'\x00\x00\x00\x00')
                log.info("DISCOVERY from %s ch=%d payload=%s%s",
                         format_mac(frame.mac), channel, frame.payload.hex(),
                         " [ADOPTED-FORM]" if adopted_form else "")

                # Firmware-version-aware session KDF context for a fresh pair:
                # v2 (payload[0]==0x02) uses the default adoption key, v1 the
                # pairing key. Skip if the operator pinned --kdf-context or we've
                # already rotated to addDevice keys (adopted-form reconnect).
                if (not self._kdf_context_explicit and not self._adopted
                        and not adopted_form):
                    self._kdf_context = initial_pairing_kdf_context(
                        frame.payload, self.pairing_key)

                # Commit observed: rotate to operational keys — session KDF
                # context = primary addDevice.key, handshake transport key =
                # fallbackKey (the reconnect 0x62/0x42 are encrypted with the
                # fallbackKey, not the pairing key). Only now is rotation safe.
                if (adopted_form and self._adopt_pending and not self._adopted
                        and self._derived_addDevice_key
                        and self._derived_addDevice_fb_key):
                    self._kdf_context = self._derived_addDevice_key
                    self._transport_key = self._derived_addDevice_fb_key
                    self._adopted = True
                    self._adopt_pending = False
                    self._privkey, self._pubkey = generate_keypair()
                    log.info("*** COMMIT OBSERVED *** rotated: KDF ctx=%s "
                             "transport(fallbackKey)=%s",
                             self._kdf_context[:8].hex(),
                             self._transport_key[:8].hex())
                    self._on_commit()

                # Build 0x62 ConnectionRsp on paired DL channel.
                if 1 <= channel <= 8:
                    dl_freq = DL_FREQ_HZ[channel - 1]
                    self._tx_seq_hi = (self._tx_seq_hi + 1) & 0xFF

                    # 0x62 ConnRsp plaintext payload (41 bytes), per the
                    # captured real-gateway frame. Marker `03 fe ff 03` at [37:41].
                    inner_payload = (
                        b'\x01\x01'
                        + self._pubkey
                        + b'\x0a\x00\x02'
                        + b'\x03\xfe\xff\x03'
                    )

                    header = bytes([0xE0, 0x62]) + frame.mac + bytes([
                        self._tx_seq_hi, self._tx_seq_lo])
                    mic = compute_mic(header, inner_payload)
                    tx_frame = build_frame(
                        0xE0, 0x62, frame.mac,
                        self._tx_seq_hi, self._tx_seq_lo,
                        mic, inner_payload,
                        self._transport_key, counter=0,
                    )
                    log.info("TX 0x62 ConnRsp to %s on %.1f MHz (%d bytes, "
                             "pubkey=%s...)", format_mac(frame.mac),
                             dl_freq / 1e6, len(tx_frame),
                             self._pubkey[:8].hex())
                    return frame, [OutgoingFrame(data=tx_frame, freq_hz=dl_freq,
                                                 channel=channel)], events

            return frame, [], events

        elif frame.dctrl == 0x42:
            # ConnectionChallenge — extract sensor's DH pubkey, establish session
            # counter=0: pass seq_hi as offset so seq_hi - offset = 0.
            # Transport key: pairing key pre-adoption, fallbackKey post-commit.
            frame = decrypt_frame(frame, self._transport_key,
                                  ul_counter_offset=frame.seq_hi)
            log.debug("0x42 PT (%dB): %s",
                      len(frame.payload) if frame.payload else 0,
                      frame.payload.hex() if frame.payload else "<empty>")
            if frame.payload is None or len(frame.payload) < 49:
                log.warning("ConnectionChallenge too short: %d bytes",
                            len(frame.payload) if frame.payload else 0)
                return frame, [], events

            # 0x42 ConnectionChallenge plaintext layout (2026-04-21 keyhook
            # capture):
            #   [0:2]   = 01 02                 outer stamp
            #   [2:3]   = 01                    type byte
            #   [3:35]  = 32B sensor pubkey
            #   [35:45] = 10B ENCRYPTED (session_key + zero nonce) ->
            #             sensor_mac (6B) || u32 (4B)
            #   [45:49] = 03 fe ff 03           fixed marker
            if frame.payload[45:49] != b'\x03\xfe\xff\x03':
                log.warning("0x42 marker mismatch at [45:49]: %s",
                            frame.payload[45:49].hex())
            self._remote_pubkey = frame.payload[3:35]
            self.sensor_mac = frame.mac
            log.info("CONN_CHALLENGE from %s pubkey=%s",
                     format_mac(frame.mac), self._remote_pubkey.hex())

            # Compute DH shared secret and derive session key.
            #   shared || gw_pub || sensor_pub || keypair+0x30_context
            shared = compute_shared_secret(self._privkey, self._remote_pubkey)
            self.session_key = derive_session_key(
                shared, self._pubkey, self._remote_pubkey,
                context=self._kdf_context,
            )
            self._ul_counter_offset = frame.seq_hi
            self._state = State.ACTIVE
            log.info("Session key derived (kdf_ctx=%s...)",
                     self._kdf_context[:8].hex())

            # Decrypt 0x42 [35:45] with session_key + zero nonce to recover the
            # 10-byte blob = sensor_mac(6B) + u32(4B). The u32 is a fresh
            # per-handshake challenge value we must echo in ChallengeRsp.
            if not _HAS_CRYPTO:
                raise RuntimeError("pysodium required for ChallengeRsp decrypt")
            blob_ct = bytes(frame.payload[35:45])
            blob_pt = pysodium.crypto_stream_xor(
                blob_ct, len(blob_ct), b'\x00' * 24, self.session_key,
            )
            echoed_sensor_mac = blob_pt[:6]
            challenge_u32 = blob_pt[6:10]
            log.info("  0x42 inner decrypt: sensor_mac=%s u32=%s",
                     format_mac(echoed_sensor_mac), challenge_u32.hex())
            if echoed_sensor_mac != frame.mac:
                log.warning("  inner sensor_mac %s != frame.mac %s "
                            "(wrong KDF context?)",
                            format_mac(echoed_sensor_mac), format_mac(frame.mac))

            # Send 0x62 ChallengeRsp on paired DL channel.
            #   inner 16B plaintext: gw_mac(6B) || sensor_mac(6B) || u32(4B)
            #   XSalsa20 session_key + 24B zero nonce, stamped "01 03".
            #   outer XSalsa20 uses the transport key.
            if 1 <= channel <= 8:
                dl_freq = DL_FREQ_HZ[channel - 1]
                self._tx_seq_hi = (self._tx_seq_hi + 1) & 0xFF

                inner_plaintext = (
                    self.gw_mac        # vec1 (6B): gateway MAC
                    + frame.mac        # vec2 (6B): sensor MAC
                    + challenge_u32    # u32  (4B): echoed from 0x42
                )
                assert len(inner_plaintext) == 16, len(inner_plaintext)

                encrypted_inner = pysodium.crypto_stream_xor(
                    inner_plaintext, len(inner_plaintext),
                    b'\x00' * 24, self.session_key,
                )

                challenge_rsp = b'\x01\x03' + encrypted_inner
                assert len(challenge_rsp) == 18

                header = bytes([0xE0, 0x62]) + frame.mac + bytes([
                    self._tx_seq_hi, self._tx_seq_lo])
                mic = compute_mic(header, challenge_rsp)
                tx_frame = build_frame(
                    0xE0, 0x62, frame.mac,
                    self._tx_seq_hi, self._tx_seq_lo,
                    mic, challenge_rsp,
                    self._transport_key, counter=0,
                )
                log.info("TX 0x62 ChallengeRsp to %s on %.1f MHz "
                         "(%d bytes outer, 16B inner encrypted)",
                         format_mac(frame.mac), dl_freq / 1e6, len(tx_frame))
                log.debug("  inner plaintext: %s", inner_plaintext.hex())
                log.debug("  inner encrypted: %s", encrypted_inner.hex())
                return frame, [OutgoingFrame(data=tx_frame, freq_hz=dl_freq,
                                             channel=channel)], events

            return frame, [], events

        return None, [], events
