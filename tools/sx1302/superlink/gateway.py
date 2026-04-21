"""
SuperLink standalone gateway.

Implements the connection state machine for pairing with
factory-default sensors via Curve25519 DH exchange.
"""

import argparse
import csv
import enum
import logging
import struct
import sys
import time
from datetime import datetime, timezone

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
                 kdf_context: bytes | None = None):
        self.gw_mac = gw_mac
        self.pairing_key = pairing_key
        self.beacon_interval = beacon_interval
        # keypair+0x30 context fed into the session-key KDF. Defaults to the
        # pairing_key; can be overridden to try values captured from a real
        # bridge (e.g. via tools/keyhook).
        self._kdf_context = kdf_context if kdf_context is not None else pairing_key

        self.state = State.IDLE
        self.sensor_mac: bytes | None = None
        self.session_key: bytes | None = None

        # DH state
        self._privkey: bytes | None = None
        self._pubkey: bytes | None = None
        self._remote_pubkey: bytes | None = None

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

        # Post-pairing management replies: 0x53 → 0x74 `0958`, 0x44 → 0x74
        # `0b5911010d14`, 0x43 → 0x74 `025a…048f` (70B session blob from
        # bridge capture). All encrypted with session_key; counter
        # increments per DL frame starting at 0.
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

            # Empirical bodies from bridge capture for the equivalent flow
            # (session_key = 8ef9826a... which corresponds to context
            # c5923a86...). These values are likely session-specific; if
            # the sensor rejects we'll need to RE how the middle bytes are
            # derived.
            if frame.dctrl == 0x53:
                body = bytes.fromhex("0958")   # reply to 0x53 `0100`
            elif frame.dctrl == 0x44:
                body = bytes.fromhex("0b5911010d14")   # reply to 0x44 setup
            else:  # 0x43
                # 70-byte session blob copied from bridge capture
                # (session_key=8ef9826a…, seq=03.41, counter=2).
                # Contents likely session-derived; this is a literal copy
                # as a first attempt. May need to be reconstructed.
                body = bytes.fromhex(
                    "025a69b5f40432f45deb2c4a72698faaeb0e31e69899bb63"
                    "f3a25693e8d49dbb5575ad5accbc18327558bb5f4bf3b870"
                    "d3e6d8bf747876e50be8613b806dbb1170210000048f"
                )

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

        return frame, None, 0

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

    session = GatewaySession(
        gw_mac=gw_mac,
        pairing_key=bytes.fromhex(
            "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
        ),
        beacon_interval=args.beacon_interval,
        kdf_context=kdf_context,
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
