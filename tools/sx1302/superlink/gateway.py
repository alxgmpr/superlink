"""
SuperLink standalone gateway.

Implements the connection state machine for pairing with
factory-default sensors via Curve25519 DH exchange.
"""

import argparse
import csv
import enum
import logging
import secrets
import struct
import sys
import time
from datetime import datetime, timezone

from .adopt import (
    DEFAULT_NETWORK_ID,
    MSG_ADOPT_RESPONSE,
    decode_adopt_response,
    encode_adopt_request,
    kdf_E,
)
from .crypto import generate_keypair, compute_shared_secret, derive_session_key
from .decoder import (
    build_frame, build_nonce, compute_mic, decrypt_frame, encrypt_payload,
    format_mac, parse_frame, SuperLinkFrame, DCTRL_TABLE,
)

try:
    import pysodium
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

log = logging.getLogger(__name__)


class State(enum.Enum):
    IDLE = "idle"
    BEACONING = "beaconing"
    WAIT_CONNREQ = "wait_connreq"
    DH_EXCHANGE = "dh_exchange"
    CHALLENGE = "challenge"
    SETUP = "setup"
    ACTIVE = "active"


class GatewaySession:
    """Manages a single sensor connection lifecycle."""

    def __init__(self, gw_mac: bytes, pairing_key: bytes,
                 beacon_interval: float = 240.0,
                 kdf_context: bytes | None = None,
                 mgmt_counter_start: int = 0x7c,
                 network_id: int = DEFAULT_NETWORK_ID,
                 sweep=None):
        self.gw_mac = gw_mac
        self.pairing_key = pairing_key
        self.beacon_interval = beacon_interval
        # Optional PROPERTY_REQUEST memory-disclosure sweep. When set, the
        # gateway probes the adopted sensor on each 0x54 data-frame RX window.
        self.sweep = sweep
        self._sweep_tag = 0
        # keypair+0x30 context fed into the session-key KDF. Defaults to the
        # pairing_key; can be overridden to try values captured from a real
        # bridge (e.g. via tools/keyhook).
        self._kdf_context = kdf_context if kdf_context is not None else pairing_key
        self.mgmt_counter_start = mgmt_counter_start
        # Console networkId (4-byte BE trailer in ADOPT_REQUEST). Per-console;
        # any 32-bit value works as long as the same one is used for the life
        # of this gateway against this sensor.
        self.network_id = network_id

        self.state = State.IDLE
        self.sensor_mac: bytes | None = None
        self.session_key: bytes | None = None
        # Set once the ADOPT round-trip completes; thereafter the KDF context
        # is the rotated addDevice.key and handshakes are operational reconnects.
        self._adopted = False

        # DH state (LoRa-side, between us and the sensor)
        self._privkey: bytes | None = None
        self._pubkey: bytes | None = None
        self._remote_pubkey: bytes | None = None

        # Application-layer ADOPT_REQUEST ephemeral privates. Set when we
        # send the 70B ADOPT_REQUEST as the 0x43 reply; consumed when the
        # sensor's ADOPT_RESPONSE comes back (decrypted body[0]==0x03).
        # Discarded after one round-trip — fresh per pair attempt.
        self._eph_priv_r: bytes | None = None
        self._eph_priv_o: bytes | None = None
        # Persistent keys derived from the ADOPT round-trip, ready to seed
        # the LoRa-session KDF context on a future re-pair (out of scope for
        # this single-session test, but logged so we can capture them).
        self._derived_addDevice_key: bytes | None = None
        self._derived_addDevice_fb_key: bytes | None = None

        # Sequence counters
        self._tx_seq_hi = 0
        self._tx_seq_lo = 0
        self._ul_counter_offset = 0

        # Timing
        self._last_beacon_time = 0.0

    def start(self):
        """Transition from IDLE to BEACONING."""
        self._privkey, self._pubkey = generate_keypair()
        self.state = State.BEACONING
        if hasattr(self, "_mgmt_counter"):
            del self._mgmt_counter
        self._last_beacon_time = 0.0  # force immediate first beacon
        log.info("Gateway started, entering BEACONING state")

    def beacon_due(self) -> bool:
        """Check if it's time to send a beacon."""
        if self.state != State.BEACONING:
            return False
        return (time.monotonic() - self._last_beacon_time) >= self.beacon_interval

    def build_beacon(self) -> bytes:
        """Build a plaintext beacon frame.

        NOTE: The exact beacon payload format is unknown. This builds a
        minimal beacon with just the header. The payload must be determined
        by capturing a real beacon from the Ubiquiti gateway.
        """
        mctrl = 0x00
        dctrl = 0x00  # TBD — beacon dctrl value unknown
        seq_hi = self._tx_seq_hi & 0xFF
        seq_lo = self._tx_seq_lo & 0xFF
        header = bytes([mctrl, dctrl]) + self.gw_mac + bytes([seq_hi, seq_lo])
        self._last_beacon_time = time.monotonic()
        log.info("Built beacon frame (%d bytes)", len(header))
        return header

    def handle_rx(self, raw: bytes, ul_channel: int = 0
                  ) -> tuple[SuperLinkFrame | None, bytes | None, int]:
        """Process a received frame based on current state.

        Args:
            raw: Raw frame bytes from HAL.
            ul_channel: UL channel number (1-8) the frame was received on.

        Returns:
            (frame, tx_data, tx_freq_hz):
              frame: Decoded frame if successfully processed, None otherwise.
              tx_data: Raw bytes to transmit in response, or None.
              tx_freq_hz: Frequency in Hz for the TX, or 0.
        """
        frame = parse_frame(raw)
        if frame is None:
            return None, None, 0

        if self.state == State.ACTIVE:
            return self._handle_active(frame, ul_channel)
        elif self.state == State.BEACONING:
            return self._handle_beaconing(frame, ul_channel)

        log.debug("RX in %s state: dctrl=0x%02X from %s (no handler)",
                  self.state.value, frame.dctrl, format_mac(frame.mac))
        return None, None, 0

    def _handle_active(self, frame: SuperLinkFrame, ul_channel: int = 0
                       ) -> tuple[SuperLinkFrame | None, bytes | None, int]:
        """Handle frames in ACTIVE state — decrypt UL, emit any DL response."""
        if self.sensor_mac and frame.mac != self.sensor_mac:
            return None, None, 0
        if self.session_key is None:
            return None, None, 0
        if frame.dctrl not in (0x54, 0x44, 0x40, 0x53, 0x43):
            log.info("RX dctrl=0x%02X seq=%02X.%02X (ignored in ACTIVE)",
                     frame.dctrl, frame.seq_hi, frame.seq_lo)
            return None, None, 0

        # 0x40 discovery: pairing_key + counter=0.
        # 0x53 / 0x43 post-pairing management: session_key + counter=0 (same
        #   zero-counter pattern as 0x40, confirmed from real-bridge capture
        #   NONCE=e053<mac><seq>00000000... with key=session_key).
        # 0x54 / 0x44 data: session_key + counter = seq_hi - ul_counter_offset.
        if frame.dctrl == 0x40:
            frame = decrypt_frame(frame, self.pairing_key,
                                  ul_counter_offset=frame.seq_hi)
        elif frame.dctrl in (0x53, 0x43):
            # dl_counter=0 forces counter=0 regardless of the DCTRL_TABLE
            # direction label (decoder currently marks 0x43/0x53 as DL;
            # empirically we receive them UL from the sensor, and the
            # real bridge capture shows counter=0 for both).
            frame = decrypt_frame(frame, self.session_key,
                                  ul_counter_offset=frame.seq_hi,
                                  dl_counter=0)
        else:
            frame = decrypt_frame(frame, self.session_key,
                                  ul_counter_offset=self._ul_counter_offset)
        log.info("RX dctrl=0x%02X %s seq=%02X.%02X %s",
                 frame.dctrl, format_mac(frame.mac),
                 frame.seq_hi, frame.seq_lo,
                 frame.interpretation or
                 (frame.payload.hex() if frame.payload else "?"))

        # Application-layer ADOPT_RESPONSE body inspection. Sensor wraps the
        # 66-byte ADOPT_RESPONSE inside a 0x54 (data UL) frame after we send
        # the ADOPT_REQUEST. Body layout: [0x03] [tag] [32B devicePub] [32B
        # deviceFbPub]. We feed the two pubkeys through kdf_E with the
        # ephemeral privates we stashed on TX to derive the new persistent
        # (addDevice.key, fallbackKey), then ship the post-rotation
        # `09 / 0b / 09` burst that signals "adoption complete" to the sensor
        # (matches what the real UniFi controller does via sendMessage —
        # without this burst the sensor times out and retries 0x43).
        if (frame.payload and len(frame.payload) >= 66
                and frame.payload[0] == MSG_ADOPT_RESPONSE
                and 1 <= ul_channel <= 8):
            try:
                tag, dev_pub, dev_fb_pub = decode_adopt_response(
                    frame.payload[:66])
            except ValueError as exc:
                log.warning("malformed ADOPT_RESPONSE body: %s", exc)
                return frame, None, 0
            if not (self._eph_priv_r and self._eph_priv_o):
                log.warning(
                    "ADOPT_RESPONSE received but no ephemeral state "
                    "stored — did we send the ADOPT_REQUEST?")
                return frame, None, 0

            self._derived_addDevice_key = kdf_E(
                self._eph_priv_r, dev_pub)
            self._derived_addDevice_fb_key = kdf_E(
                self._eph_priv_o, dev_fb_pub)
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

            # Adoption-confirm: a SINGLE 6-byte 0x74 `0e NN 0d 00 01 2c`
            # frame. This is byte-exact ground truth from real-bridge
            # pair5/pair6 keyhook captures — NOT the old 3-frame 09/0b/09
            # burst (a Y4-mock artifact the sensor rejects, sending it back
            # into the 0x43 retry loop). NN continues the DL-management
            # counter; the frame's DL-data counter continues via
            # _build_0x74_reply's _post_pair_* progression.
            from .hal import DL_FREQ_HZ
            dl_freq = DL_FREQ_HZ[ul_channel - 1]
            # Commit ack: the real bridge answers ADOPT_RESPONSE with a single
            # 0x63 REQUEST_STATUS_RESPONSE(status=OK) body `01 00` — verified
            # ground truth from a fresh adoption capture
            # (bridge_adopt_fresh_pass2_20260722.log). The `0e NN 0d 00 01 2c`
            # we sent before is actually a PROPERTY_SET(REPORT_INTERVAL=300)
            # config write the controller sends LATER; sending it here (a
            # malformed reply before device info) is why the sensor never
            # committed.
            confirm_body = bytes([0x01, 0x00])
            tx_frame = self._build_dl_reply(frame.mac, confirm_body, dctrl=0x63)
            log.info("adoption commit-ack TX 0x63 on %.1f MHz (body=%s)",
                     dl_freq / 1e6, confirm_body.hex())

            # Rotate to operational mode. Post-adoption the sensor reconnects
            # with a fresh 0x40→0x62→0x42→0x62 handshake and BOTH sides derive
            # the session key with addDevice.key as the KDF context — verified
            # against real-bridge ground truth (op key 9432ba8e, capture
            # bridge_pair_keyhook_20260722.log). Swap in the rotated context,
            # mint a fresh keypair for the reconnect, and drop back to
            # BEACONING so the existing handshake path derives the operational
            # session key correctly. (The confirm above is already encrypted
            # under the OLD session key — the rotation only affects the next
            # handshake.)
            self._kdf_context = self._derived_addDevice_key
            self._privkey, self._pubkey = generate_keypair()
            self.state = State.BEACONING
            self._adopted = True
            log.info("adopted — rotated KDF context to addDevice.key %s; "
                     "awaiting operational reconnect",
                     self._derived_addDevice_key.hex())
            return frame, tx_frame, dl_freq

        # Post-pairing management replies: 0x53 → 0x74 `09 NN`, 0x44 → 0x74
        # `0b NN+1 11 01 0d 14`, 0x43 → 0x74 ADOPT_REQUEST. NN is a
        # per-session DL-management counter that increments by 1 on each
        # reply. The sensor appears to accept any starting value as long as
        # consecutive replies increment by 1.
        #
        # Y5 (2026-04-30): the 0x43 reply IS an ADOPT_REQUEST per
        # docs/protocol/superlink_application_layer.md — fresh ephemeral X25519
        # keypairs per pair attempt, not the captured-pair4-bytes-with-masks
        # blind-search the prior code was doing.
        if frame.dctrl in (0x53, 0x44, 0x43) and 1 <= ul_channel <= 8:
            from .hal import DL_FREQ_HZ
            dl_freq = DL_FREQ_HZ[ul_channel - 1]

            self._post_pair_tx_seq_hi = getattr(
                self, "_post_pair_tx_seq_hi", 0) + 1
            self._post_pair_tx_seq_lo = getattr(
                self, "_post_pair_tx_seq_lo", 0) + 1
            self._post_pair_counter = getattr(
                self, "_post_pair_counter", -1) + 1
            seq_hi = self._post_pair_tx_seq_hi & 0xFF
            seq_lo = self._post_pair_tx_seq_lo & 0xFF
            counter = self._post_pair_counter

            # Per-session DL-management counter (position 1 of each reply
            # body). Initialize on first use. The starting value is
            # configurable via --mgmt-counter-start (default 0x7c matches
            # pair4 capture); subsequent replies increment by 1.
            if not hasattr(self, "_mgmt_counter"):
                self._mgmt_counter = getattr(self, "mgmt_counter_start", 0x7c)
            mgmt = self._mgmt_counter & 0xFF
            self._mgmt_counter += 1

            if frame.dctrl == 0x53:
                body = bytes([0x09, mgmt])
            elif frame.dctrl == 0x44:
                body = bytes([0x0b, mgmt, 0x11, 0x01, 0x0d, 0x14])
            else:  # 0x43 — emit a fresh ADOPT_REQUEST per Y5
                if not _HAS_CRYPTO:
                    raise RuntimeError(
                        "pysodium required for ADOPT_REQUEST keypair generation")
                # Fresh ephemeral keypair per pair attempt — never reuse.
                # Stashed on `self` so the matching ADOPT_RESPONSE handler
                # can derive the rotated persistent keys via kdf_E.
                self._eph_priv_r = secrets.token_bytes(32)
                self._eph_priv_o = secrets.token_bytes(32)
                gw_pub = pysodium.crypto_scalarmult_curve25519_base(
                    self._eph_priv_r)
                gw_fb_pub = pysodium.crypto_scalarmult_curve25519_base(
                    self._eph_priv_o)
                body = encode_adopt_request(
                    mgmt, gw_pub, gw_fb_pub, self.network_id)
                log.info(
                    "ADOPT_REQUEST tag=0x%02x gw_pub=%s gw_fb_pub=%s "
                    "networkId=0x%x",
                    mgmt, gw_pub.hex(), gw_fb_pub.hex(), self.network_id)

            header = bytes([0xE0, 0x74]) + frame.mac + bytes([seq_hi, seq_lo])
            mic = compute_mic(header, body)
            tx_frame = build_frame(
                0xE0, 0x74, frame.mac, seq_hi, seq_lo,
                mic, body,
                self.session_key, counter=counter,
            )
            log.info("TX 0x74 reply to 0x%02X on %.1f MHz "
                     "(seq=%02X.%02X counter=%d body=%s)",
                     frame.dctrl, dl_freq / 1e6, seq_hi, seq_lo,
                     counter, body.hex())
            return frame, tx_frame, dl_freq

        # Sweep mode (post-adoption): capture any report, and use the sensor's
        # data-frame RX window to send the next PROPERTY_REQUEST probe. Gated
        # to 0x54 data frames so the adoption handshake above is never touched.
        if self.sweep is not None:
            self._ingest_app_report(frame.payload)
            if frame.dctrl == 0x54 and 1 <= ul_channel <= 8:
                body = self._next_probe_body()
                if body is not None:
                    from .hal import DL_FREQ_HZ
                    dl_freq = DL_FREQ_HZ[ul_channel - 1]
                    tx_frame = self._build_0x74_reply(frame.mac, body)
                    log.info("SWEEP probe -> %s on %.1f MHz body=%s",
                             format_mac(frame.mac), dl_freq / 1e6, body.hex())
                    return frame, tx_frame, dl_freq
                if self.sweep.done():
                    log.info("SWEEP complete: %s", self.sweep.summary())

        return frame, None, 0

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
        # Send DEVICE_INFO_REQUEST until we've got a report back.
        if self.sweep.device_info is None:
            return appmsg.encode_device_info_request(tag=self._sweep_tag)
        batch = self.sweep.next_batch()
        if not batch:
            return None
        return appmsg.encode_property_request(batch, tag=self._sweep_tag)

    def _build_dl_reply(self, mac: bytes, body: bytes, dctrl: int = 0x74) -> bytes:
        """Build an encrypted DL frame carrying an app-message body.

        Continues the post-pairing seq/counter progression (shared DL-data
        counter) so consecutive DL frames — 0x74 mgmt replies/probes and the
        0x63 commit ack — stay in sequence for the sensor's nonce.
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

    def _ingest_app_report(self, payload: bytes) -> None:
        """Route a decrypted UL app message into the sweep controller."""
        if self.sweep is None or not payload or len(payload) < 2:
            return
        from . import appmsg
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

    def _handle_beaconing(self, frame: SuperLinkFrame, ul_channel: int = 0
                          ) -> tuple[SuperLinkFrame | None, bytes | None, int]:
        """Handle frames in BEACONING state.

        Listens for:
        - 0x40 discovery ads: respond with 0x62 ConnectionRsp (DH pubkey)
        - 0x42 ConnectionChallenge: extract pubkey, do DH, derive session key
        """
        from .hal import DL_FREQ_HZ, BW_500KHZ

        if frame.dctrl == 0x40:
            # Discovery advertisement — decrypt with default pairing key
            # counter=0: pass seq_hi as offset so seq_hi - offset = 0
            frame = decrypt_frame(frame, self.pairing_key, ul_counter_offset=frame.seq_hi)
            if frame.payload and len(frame.payload) >= 2 and frame.payload[0] == 0x01:
                self.sensor_mac = frame.mac
                log.info("DISCOVERY from %s ch=%d payload=%s",
                         format_mac(frame.mac), ul_channel, frame.payload.hex())

                # Build 0x62 ConnectionRsp on paired DL channel
                # dctrl=0x62: lower 3 bits = 2 → connection handler (sub_524ac)
                # Captured from real Ubiquiti gateway DL response.
                # Sensor dispatches via inner type switch:
                #   case 0 → sub_51914 (initial pairing: extract pubkey, send 0x42)
                #   case 2 → sub_52090 (reconnection/challenge)
                if 1 <= ul_channel <= 8:
                    dl_freq = DL_FREQ_HZ[ul_channel - 1]
                    self._tx_seq_hi = (self._tx_seq_hi + 1) & 0xFF

                    # 0x62 ConnRsp plaintext payload (41 bytes), per the
                    # captured real-gateway frame. Marker `03 fe ff 03`
                    # lives at [37:41] (end of payload for ConnRsp).
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
                        self.pairing_key, counter=0,
                    )
                    log.info("TX 0x62 ConnRsp to %s on %.1f MHz (%d bytes, pubkey=%s...)",
                             format_mac(frame.mac), dl_freq / 1e6, len(tx_frame),
                             self._pubkey[:8].hex())
                    return frame, tx_frame, dl_freq

            return frame, None, 0

        elif frame.dctrl == 0x42:
            # ConnectionChallenge — extract sensor's DH pubkey and establish session
            # counter=0: pass seq_hi as offset so seq_hi - offset = 0
            frame = decrypt_frame(frame, self.pairing_key, ul_counter_offset=frame.seq_hi)
            log.info("0x42 PT (%dB): %s",
                     len(frame.payload) if frame.payload else 0,
                     frame.payload.hex() if frame.payload else "<empty>")
            if frame.payload is None or len(frame.payload) < 49:
                log.warning("ConnectionChallenge too short: %d bytes",
                            len(frame.payload) if frame.payload else 0)
                return frame, None, 0

            # 0x42 ConnectionChallenge plaintext layout, corrected per the
            # 2026-04-21 LD_PRELOAD keyhook capture of a real Ubi bridge:
            #   [0:2]   = 01 02                 outer stamp
            #   [2:3]   = 01                    type byte
            #   [3:35]  = 32B sensor pubkey
            #   [35:45] = 10B ENCRYPTED with session_key + zero nonce,
            #             decrypts to: sensor_mac (6B) || u32 (4B)
            #   [45:49] = 03 fe ff 03           fixed marker
            #   [49:N]  = optional tail
            #
            # Earlier RE mis-interpreted [35:41] and [41:45] as plaintext
            # "state vec" and "state u32" — they are actually ciphertext of a
            # 10-byte session-key-encrypted blob.
            if frame.payload[45:49] != b'\x03\xfe\xff\x03':
                log.warning("0x42 marker mismatch at [45:49]: %s",
                            frame.payload[45:49].hex())
            self._remote_pubkey = frame.payload[3:35]
            self.sensor_mac = frame.mac
            log.info("CONN_CHALLENGE from %s pubkey=%s",
                     format_mac(frame.mac), self._remote_pubkey.hex())

            # Compute DH shared secret and derive session key.
            # Firmware sub_3af5a hashes in order (after is_initiator swap):
            #   shared || gw_pub || sensor_pub || keypair+0x30_context
            # The keypair+0x30 context is a per-device 32-byte value the bridge
            # persists. For a factory-default sensor the expected value is
            # unknown — we try pairing_key first; can be overridden by CLI.
            shared = compute_shared_secret(self._privkey, self._remote_pubkey)
            self.session_key = derive_session_key(
                shared, self._pubkey, self._remote_pubkey,
                context=self._kdf_context,
            )
            # FULL DEBUG DUMP — temp instrumentation for offline KDF analysis.
            log.info("DBG gw_priv=%s gw_pub=%s sensor_pub=%s shared=%s session_key=%s kdf_ctx=%s",
                     self._privkey.hex(), self._pubkey.hex(),
                     self._remote_pubkey.hex(), shared.hex(),
                     self.session_key.hex(), self._kdf_context.hex())
            log.info("DBG blob_ct=%s 0x42_frame_seq=%02X.%02X mac=%s",
                     bytes(frame.payload[35:45]).hex(),
                     frame.seq_hi, frame.seq_lo,
                     format_mac(frame.mac))
            self._ul_counter_offset = frame.seq_hi
            self.state = State.ACTIVE
            log.info("Session key derived (kdf_ctx=%s...)",
                     self._kdf_context[:8].hex())

            # Decrypt 0x42 [35:45] with session_key + zero nonce to recover
            # the 10-byte blob = sensor_mac(6B) + u32(4B). The u32 is a fresh
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
                log.warning("  inner sensor_mac %s != frame.mac %s (wrong KDF context?)",
                            format_mac(echoed_sensor_mac), format_mac(frame.mac))

            # Send 0x62 ChallengeRsp on paired DL channel.
            #
            # Inner 16-byte plaintext (per real-bridge capture):
            #   gw_mac (6B) || sensor_mac (6B) || u32 (4B — echoed from 0x42)
            # XSalsa20 with session_key + 24-byte zero nonce, stamped with "01 03".
            # Outer XSalsa20 uses pairing_key.
            if 1 <= ul_channel <= 8:
                dl_freq = DL_FREQ_HZ[ul_channel - 1]
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
                    self.pairing_key, counter=0,
                )
                log.info("TX 0x62 ChallengeRsp to %s on %.1f MHz "
                         "(%d bytes outer, 16B inner encrypted)",
                         format_mac(frame.mac), dl_freq / 1e6, len(tx_frame))
                log.info("  inner plaintext: %s", inner_plaintext.hex())
                log.info("  inner encrypted: %s", encrypted_inner.hex())
                return frame, tx_frame, dl_freq

            return frame, None, 0

        return None, None, 0


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
    if args.sweep:
        from .sweep import PropertySweep, parse_id_spec
        try:
            ids = parse_id_spec(args.sweep)
        except ValueError as e:
            print(f"Error: invalid --sweep IDS: {e}", file=sys.stderr)
            sys.exit(1)
        sweep = PropertySweep(ids=ids, batch_size=args.sweep_batch)
        log.info("PROPERTY_REQUEST sweep enabled: %d ids, batch=%d",
                 len(ids), args.sweep_batch)

    session = GatewaySession(
        gw_mac=gw_mac,
        pairing_key=bytes.fromhex(
            "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
        ),
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
                    hal.send(tx_freq, tx_data, bandwidth=BW_500KHZ,
                             tx_timestamp_us=tx_ts,
                             invert_pol=args.invert_iq)
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
