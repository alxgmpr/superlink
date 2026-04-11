"""
SuperLink standalone gateway.

Implements the connection state machine for pairing with
factory-default sensors via Curve25519 DH exchange.
"""

import enum
import logging
import time

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
        """Handle frames in BEACONING state — look for ConnectionReq."""
        # TODO: Parse ConnectionReq, extract sensor pubkey, transition to DH_EXCHANGE
        # This requires knowing the ConnectionReq frame format (capture needed)
        log.debug("RX in BEACONING: dctrl=0x%02X from %s (not yet handled)",
                  frame.dctrl, format_mac(frame.mac))
        return None
