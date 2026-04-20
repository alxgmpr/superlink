"""
SuperLink standalone gateway.

Implements the connection state machine for pairing with
factory-default sensors via Curve25519 DH exchange.
"""

import argparse
import csv
import enum
import logging
import sys
import time
from datetime import datetime, timezone

from .crypto import generate_keypair, compute_shared_secret, derive_session_key
from .decoder import (
    build_frame, build_nonce, compute_mic, decrypt_frame, encrypt_payload,
    format_mac, parse_frame, SuperLinkFrame, DCTRL_TABLE,
)

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
                 beacon_interval: float = 240.0):
        self.gw_mac = gw_mac
        self.pairing_key = pairing_key
        self.beacon_interval = beacon_interval

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
            return self._handle_active(frame), None, 0
        elif self.state == State.BEACONING:
            return self._handle_beaconing(frame, ul_channel)

        log.debug("RX in %s state: dctrl=0x%02X from %s (no handler)",
                  self.state.value, frame.dctrl, format_mac(frame.mac))
        return None, None, 0

    def _handle_active(self, frame: SuperLinkFrame) -> SuperLinkFrame | None:
        """Handle frames in ACTIVE state — decrypt UL data."""
        if self.sensor_mac and frame.mac != self.sensor_mac:
            return None
        if self.session_key is None:
            return None
        if frame.dctrl not in (0x54, 0x44, 0x40):
            log.info("RX dctrl=0x%02X seq=%02X.%02X (ignored in ACTIVE)",
                     frame.dctrl, frame.seq_hi, frame.seq_lo)
            return None

        # 0x40 discovery always uses pairing key + counter=0 (sensor never
        # increments the stream-counter for discoveries). Using the session
        # offset here would produce garbage.
        if frame.dctrl == 0x40:
            frame = decrypt_frame(frame, self.pairing_key,
                                  ul_counter_offset=frame.seq_hi)
        else:
            frame = decrypt_frame(frame, self.session_key,
                                  ul_counter_offset=self._ul_counter_offset)
        log.info("RX dctrl=0x%02X %s seq=%02X.%02X %s",
                 frame.dctrl, format_mac(frame.mac),
                 frame.seq_hi, frame.seq_lo,
                 frame.interpretation or
                 (frame.payload.hex() if frame.payload else "?"))
        return frame

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

            # 0x42 ConnectionChallenge plaintext layout. Real pairing
            # capture (2026-04-20) shows the challenge can be 49 OR 63 bytes.
            # `03 fe ff 03` is a FIXED-POSITION MARKER at [45:49], NOT a
            # trailer — the 63B variant has 14 more bytes after it.
            #   [0:2]   = 01 02                 outer type, inner_type=Challenge
            #   [2:13]  = 11-byte state header
            #   [13:45] = 32-byte sensor pubkey
            #   [45:49] = 03 fe ff 03           fixed marker
            #   [49:N]  = optional tail (0 bytes for 49B frame,
            #                            14 bytes for 63B frame)
            if frame.payload[45:49] != b'\x03\xfe\xff\x03':
                log.warning("0x42 marker mismatch at [45:49]: %s",
                            frame.payload[45:49].hex())
            self._remote_pubkey = frame.payload[13:45]
            self.sensor_mac = frame.mac
            log.info("CONN_CHALLENGE from %s pubkey=%s",
                     format_mac(frame.mac), self._remote_pubkey.hex())

            # Compute DH shared secret and derive session key.
            # Firmware sub_3af5a hashes in the order: shared || r6 || r8 where
            # r6 starts as remote pubkey and r8 starts as local pubkey, then
            # they get SWAPPED when is_initiator==0 (the gateway case). So
            # after the swap the hash order is: shared || local || remote
            # = shared || gateway_pub || sensor_pub. For the sensor (initiator)
            # no swap occurs, r6=remote=gateway_pub r8=local=sensor_pub, same
            # hash order — ensuring both sides derive the same key.
            shared = compute_shared_secret(self._privkey, self._remote_pubkey)
            self.session_key = derive_session_key(shared, self._pubkey, self._remote_pubkey)
            self._ul_counter_offset = frame.seq_hi
            self.state = State.ACTIVE
            log.info("Session key derived, entering ACTIVE state (counter_offset=%d)",
                     self._ul_counter_offset)

            # Send 0x62 ChallengeRsp on paired DL channel.
            # Firmware sub_52090 builds this via the same sub_444b8 path but
            # calls sub_439f0(obj, 3) instead of 1 — so inner_type=3.
            # Payload layout mirrors 0x62 ConnRsp:
            #   [0:2]   = 01 03           (outer type, inner_type=ChallengeRsp)
            #   [2:34]  = 32-byte gateway pubkey (SAME keypair as ConnRsp)
            #   [34:37] = 0a 00 02
            #   [37:41] = 03 fe ff 03     (ChMap trailer)
            if 1 <= ul_channel <= 8:
                dl_freq = DL_FREQ_HZ[ul_channel - 1]
                self._tx_seq_hi = (self._tx_seq_hi + 1) & 0xFF

                challenge_rsp = (
                    b'\x01\x03'
                    + self._pubkey
                    + b'\x0a\x00\x02'
                    + b'\x03\xfe\xff\x03'
                )
                header = bytes([0xE0, 0x62]) + frame.mac + bytes([
                    self._tx_seq_hi, self._tx_seq_lo])
                mic = compute_mic(header, challenge_rsp)
                tx_frame = build_frame(
                    0xE0, 0x62, frame.mac,
                    self._tx_seq_hi, self._tx_seq_lo,
                    mic, challenge_rsp,
                    self.pairing_key, counter=0,
                )
                log.info("TX 0x62 ChallengeRsp to %s on %.1f MHz (%d bytes)",
                         format_mac(frame.mac), dl_freq / 1e6, len(tx_frame))
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

    session = GatewaySession(
        gw_mac=gw_mac,
        pairing_key=bytes.fromhex(
            "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
        ),
        beacon_interval=args.beacon_interval,
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
