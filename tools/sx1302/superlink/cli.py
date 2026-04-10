"""
Interactive CLI for the SX1302 SuperLink sniffer.

Color-coded live output with filtering, stats, and CSV logging.
Ties together the HAL (hardware) and decoder (frame parsing) modules.
"""

import argparse
import csv
import io
import os
import select
import sys
import termios
import time
import tty
from datetime import datetime, timezone

from .decoder import SuperLinkFrame, decrypt_frame, format_mac, parse_frame
from .hal import SX1302, RxPacket

# --- ANSI color constants ---

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_CYAN = "\033[36m"

# --- Stats tracking ---


class Stats:
    """Packet statistics tracker."""

    def __init__(self):
        self.total = 0
        self.crc_ok = 0
        self.crc_bad = 0
        self.per_mac: dict[str, int] = {}
        self.per_channel: dict[int, int] = {}
        self.rssi_sum = 0.0
        self.snr_sum = 0.0

    def record(self, pkt: RxPacket, frame: SuperLinkFrame | None):
        """Record a packet in the stats."""
        self.total += 1
        if pkt.crc_ok:
            self.crc_ok += 1
        else:
            self.crc_bad += 1

        self.rssi_sum += pkt.rssi
        self.snr_sum += pkt.snr

        ch = pkt.ul_channel
        self.per_channel[ch] = self.per_channel.get(ch, 0) + 1

        if frame is not None:
            mac_str = format_mac(frame.mac)
            self.per_mac[mac_str] = self.per_mac.get(mac_str, 0) + 1

    def display(self):
        """Print stats summary to stdout."""
        print(f"\n{C_BOLD}--- Statistics ---{C_RESET}")
        print(f"  Total packets: {self.total}")
        print(f"  CRC OK: {self.crc_ok}  CRC BAD: {self.crc_bad}")
        if self.total > 0:
            print(f"  Avg RSSI: {self.rssi_sum / self.total:.1f} dBm")
            print(f"  Avg SNR:  {self.snr_sum / self.total:.1f} dB")
        if self.per_channel:
            print(f"  {C_BOLD}Per channel:{C_RESET}")
            for ch in sorted(self.per_channel):
                print(f"    CH{ch}: {self.per_channel[ch]}")
        if self.per_mac:
            print(f"  {C_BOLD}Per MAC:{C_RESET}")
            for mac, count in sorted(self.per_mac.items(), key=lambda x: -x[1]):
                print(f"    {mac}: {count}")
        print()


# --- Packet formatting ---


def format_packet(pkt: RxPacket, frame: SuperLinkFrame | None, show_raw: bool) -> str:
    """Produce color-coded formatted output for a packet."""
    now = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    lines = []

    if frame is None:
        # Unparseable frame -- just show raw info
        crc_str = f"{C_GREEN}OK{C_RESET}" if pkt.crc_ok else f"{C_RED}BAD{C_RESET}"
        lines.append(
            f"{C_DIM}{now} CH{pkt.ul_channel} {len(pkt.payload)}B "
            f"{pkt.rssi:.0f}dBm {pkt.snr:.1f}dB CRC={crc_str} "
            f"[unparseable]{C_RESET}"
        )
        if show_raw:
            lines.append(f"  {C_DIM}{pkt.payload.hex()}{C_RESET}")
        return "\n".join(lines)

    # Direction color
    if frame.direction == "UL":
        dir_color = C_GREEN
    elif frame.direction == "DL":
        dir_color = C_BLUE
    else:
        dir_color = C_YELLOW

    mac_str = format_mac(frame.mac)
    seq_str = f"{frame.seq_hi:02X}.{frame.seq_lo:02X}"
    crc_str = f"{C_GREEN}OK{C_RESET}" if pkt.crc_ok else f"{C_RED}BAD{C_RESET}"

    # Line 1: summary
    line1 = (
        f"{now} CH{pkt.ul_channel} {dir_color}{frame.direction}{C_RESET} "
        f"{mac_str} seq={seq_str} {len(pkt.payload)}B "
        f"{pkt.rssi:.0f}dBm {pkt.snr:.1f}dB CRC={crc_str}"
    )
    if not pkt.crc_ok:
        line1 = f"{C_RED}{line1}{C_RESET}"
    lines.append(line1)

    # Line 2: detail
    mic_hex = frame.mic.hex()
    if frame.mic_valid is True:
        mic_str = f"MIC={mic_hex} {C_GREEN}ok{C_RESET}"
    elif frame.mic_valid is False:
        mic_str = f"MIC={mic_hex} {C_RED}FAIL{C_RESET}"
    else:
        mic_str = f"MIC={mic_hex} {C_DIM}--{C_RESET}"

    payload_hex = ""
    if frame.payload is not None:
        payload_hex = frame.payload.hex()
    elif frame.payload_enc:
        payload_hex = f"{C_YELLOW}{frame.payload_enc.hex()}{C_RESET}"

    interp = ""
    if frame.interpretation:
        interp = f"  {C_CYAN}{frame.interpretation}{C_RESET}"

    line2 = (
        f"  dctrl={frame.dctrl:02X} {frame.frame_type}  "
        f"{mic_str}  {payload_hex}{interp}"
    )
    lines.append(line2)

    # Optional line 3: raw hex
    if show_raw:
        lines.append(f"  {C_DIM}{pkt.payload.hex()}{C_RESET}")

    return "\n".join(lines)


# --- CSV logging ---


def log_packet(
    writer: csv.writer, pkt: RxPacket, frame: SuperLinkFrame | None
):
    """Write a CSV row for the packet."""
    now = datetime.now(timezone.utc).isoformat()
    if frame is None:
        writer.writerow([
            now, pkt.ul_channel, "", "", "", pkt.rssi, pkt.snr,
            "OK" if pkt.crc_ok else "BAD", "", "", pkt.payload.hex(), "",
        ])
    else:
        writer.writerow([
            now,
            pkt.ul_channel,
            frame.direction,
            format_mac(frame.mac),
            f"{frame.seq_hi:02X}.{frame.seq_lo:02X}",
            pkt.rssi,
            pkt.snr,
            "OK" if pkt.crc_ok else "BAD",
            f"{frame.dctrl:02X}",
            "" if frame.mic_valid is None else ("ok" if frame.mic_valid else "FAIL"),
            (frame.payload.hex() if frame.payload is not None
             else frame.payload_enc.hex()),
            frame.interpretation or "",
        ])


# --- Non-blocking key input ---


def check_keypress() -> str | None:
    """Non-blocking stdin check. Returns key character or None."""
    if select.select([sys.stdin], [], [], 0)[0]:
        return sys.stdin.read(1)
    return None


# --- Help text ---

HELP_TEXT = f"""
{C_BOLD}SuperLink SX1302 Sniffer{C_RESET}
  q  quit
  s  show statistics
  h  this help
"""


# --- Main entry point ---


def main():
    parser = argparse.ArgumentParser(
        description="SuperLink SX1302 packet sniffer"
    )
    parser.add_argument(
        "--key", metavar="HEX",
        help="Session key (64 hex chars) for decryption",
    )
    parser.add_argument(
        "--mac", metavar="MAC",
        help="Filter by MAC address (e.g. AA:BB:CC:DD:EE:FF)",
    )
    parser.add_argument(
        "--ul", action="store_true",
        help="Show only uplink packets",
    )
    parser.add_argument(
        "--dl", action="store_true",
        help="Show only downlink packets",
    )
    parser.add_argument(
        "--channel", type=int, metavar="N",
        help="Filter by channel number (1-8)",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Show raw hex dumps",
    )
    parser.add_argument(
        "--log", metavar="FILE.csv",
        help="Log packets to CSV file",
    )
    args = parser.parse_args()

    # Parse session key
    session_key: bytes | None = None
    if args.key:
        if len(args.key) != 64:
            print(f"{C_RED}Error: --key must be 64 hex characters{C_RESET}",
                  file=sys.stderr)
            sys.exit(1)
        try:
            session_key = bytes.fromhex(args.key)
        except ValueError:
            print(f"{C_RED}Error: --key must be valid hex{C_RESET}",
                  file=sys.stderr)
            sys.exit(1)

    # Parse MAC filter
    mac_filter: bytes | None = None
    if args.mac:
        try:
            mac_filter = bytes.fromhex(args.mac.replace(":", "").replace("-", ""))
            if len(mac_filter) != 6:
                raise ValueError("MAC must be 6 bytes")
        except ValueError as e:
            print(f"{C_RED}Error: invalid --mac: {e}{C_RESET}", file=sys.stderr)
            sys.exit(1)

    # Open CSV log file
    csv_file = None
    csv_writer = None
    if args.log:
        csv_file = open(args.log, "a", newline="")
        csv_writer = csv.writer(csv_file)
        if csv_file.tell() == 0:
            csv_writer.writerow([
                "timestamp", "channel", "direction", "mac", "seq",
                "rssi", "snr", "crc", "dctrl", "mic_valid",
                "payload", "interpretation",
            ])

    stats = Stats()
    old_settings = None
    hal = None

    try:
        # Set terminal to cbreak mode for non-blocking key input
        if sys.stdin.isatty():
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())

        # Start concentrator
        hal = SX1302()
        print(f"{C_BOLD}Starting SX1302 concentrator...{C_RESET}")
        hal.start()
        print(f"{C_GREEN}Concentrator started. HAL version: {hal.version()}{C_RESET}")
        print(HELP_TEXT)

        # Main receive loop
        while True:
            # Check for keyboard input
            key = check_keypress() if sys.stdin.isatty() else None
            if key == "q":
                print(f"\n{C_BOLD}Quitting...{C_RESET}")
                break
            elif key == "s":
                stats.display()
                continue
            elif key == "h":
                print(HELP_TEXT)
                continue

            # Poll for packets
            packets = hal.receive()
            if not packets:
                time.sleep(0.01)
                continue

            for pkt in packets:
                # Parse frame
                frame = parse_frame(pkt.payload)

                # Decrypt if we have a key
                if frame is not None and session_key is not None:
                    frame = decrypt_frame(frame, session_key)

                # Apply filters
                if args.channel and pkt.ul_channel != args.channel:
                    continue
                if mac_filter and frame is not None and frame.mac != mac_filter:
                    continue
                if args.ul and (frame is None or frame.direction != "UL"):
                    continue
                if args.dl and (frame is None or frame.direction != "DL"):
                    continue

                # Record stats
                stats.record(pkt, frame)

                # Format and print
                print(format_packet(pkt, frame, args.raw))

                # CSV logging
                if csv_writer is not None:
                    log_packet(csv_writer, pkt, frame)
                    csv_file.flush()

    except KeyboardInterrupt:
        print(f"\n{C_BOLD}Interrupted.{C_RESET}")
    finally:
        # Restore terminal
        if old_settings is not None:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

        # Stop concentrator
        if hal is not None:
            hal.stop()
            print(f"{C_DIM}Concentrator stopped.{C_RESET}")

        # Close CSV file
        if csv_file is not None:
            csv_file.close()

        # Print final stats
        stats.display()
