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
    build_frame, build_nonce, decrypt_frame, encrypt_payload,
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

    def handle_rx(self, raw: bytes) -> SuperLinkFrame | None:
        """Process a received frame based on current state.

        Args:
            raw: Raw frame bytes from HAL.

        Returns:
            Decoded frame if successfully processed, None otherwise.
        """
        frame = parse_frame(raw)
        if frame is None:
            return None

        if self.state == State.ACTIVE:
            return self._handle_active(frame)
        elif self.state == State.BEACONING:
            return self._handle_beaconing(frame)

        log.debug("RX in %s state: dctrl=0x%02X from %s (no handler)",
                  self.state.value, frame.dctrl, format_mac(frame.mac))
        return None

    def _handle_active(self, frame: SuperLinkFrame) -> SuperLinkFrame | None:
        """Handle frames in ACTIVE state — decrypt UL data."""
        if self.sensor_mac and frame.mac != self.sensor_mac:
            return None
        if self.session_key is None:
            return None
        if frame.dctrl not in (0x54, 0x44, 0x40):
            return None

        key = self.session_key
        if frame.dctrl == 0x40:
            key = self.pairing_key

        frame = decrypt_frame(frame, key, ul_counter_offset=self._ul_counter_offset)
        log.info("RX %s seq=%02X.%02X %s",
                 format_mac(frame.mac), frame.seq_hi, frame.seq_lo,
                 frame.interpretation or (frame.payload.hex() if frame.payload else "?"))
        return frame

    def _handle_beaconing(self, frame: SuperLinkFrame) -> SuperLinkFrame | None:
        """Handle frames in BEACONING state.

        Listens for:
        - 0x40 discovery ads: decrypt with default key, log sensor MAC
        - 0x42 ConnectionChallenge: extract pubkey, do DH, derive session key
        """
        if frame.dctrl == 0x40:
            # Discovery advertisement — decrypt with default pairing key
            # counter=0: pass seq_hi as offset so seq_hi - offset = 0
            frame = decrypt_frame(frame, self.pairing_key, ul_counter_offset=frame.seq_hi)
            if frame.payload and len(frame.payload) >= 2 and frame.payload[0] == 0x01:
                self.sensor_mac = frame.mac
                log.info("DISCOVERY from %s payload=%s",
                         format_mac(frame.mac), frame.payload.hex())
            return frame

        elif frame.dctrl == 0x42:
            # ConnectionChallenge — extract sensor's DH pubkey and establish session
            # counter=0: pass seq_hi as offset so seq_hi - offset = 0
            frame = decrypt_frame(frame, self.pairing_key, ul_counter_offset=frame.seq_hi)
            if frame.payload is None or len(frame.payload) < 49:
                log.warning("ConnectionChallenge too short: %d bytes",
                            len(frame.payload) if frame.payload else 0)
                return frame

            # Extract pubkey from payload offset 17 (32 bytes)
            self._remote_pubkey = frame.payload[17:49]
            self.sensor_mac = frame.mac
            log.info("CONN_CHALLENGE from %s pubkey=%s",
                     format_mac(frame.mac), self._remote_pubkey.hex())

            # Compute DH shared secret and derive session key
            shared = compute_shared_secret(self._privkey, self._remote_pubkey)
            # Gateway is NOT initiator: order is (remote=sensor, local=gateway)
            self.session_key = derive_session_key(shared, self._remote_pubkey, self._pubkey)
            self._ul_counter_offset = frame.seq_hi
            self.state = State.ACTIVE
            log.info("Session key derived, entering ACTIVE state (counter_offset=%d)",
                     self._ul_counter_offset)
            return frame

        return None


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
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    from .hal import SX1302

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
                frame = session.handle_rx(pkt.payload)
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
