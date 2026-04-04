#!/usr/bin/env python3
"""
SuperLink real-time packet decoder.

Reads raw packet output from the Heltec sniffer over serial,
decrypts payloads using captured session keys, and prints decoded frames.

Usage:
    python superlink_decode.py [--port /dev/cu.usbserial-0001] [--key HEX]
"""

import argparse
import re
import sys
import time
from datetime import datetime

import serial
import pysodium

# Session key (ephemeral — capture via LD_PRELOAD hook on gateway, see docs/)
# Pass your current key with --key, or set it here:
DEFAULT_SESSION_KEY = None

# ANSI colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_MAGENTA = "\033[35m"
C_CYAN = "\033[36m"

# Known Dctrl values
DCTRL_INFO = {
    0x54: ("UL", "data"),
    0x44: ("UL", "data-ext"),
    0x63: ("DL", "data"),
    0x74: ("DL", "ack"),
}

SENSOR_MAC = "90:41:B2:2E:9A:53"
GATEWAY_MAC = "90:41:B2:34:83:DC"


def decrypt_payload(mctrl, dctrl, mac_bytes, seq_hi, seq_lo, mic, payload, key):
    """Decrypt a SuperLink payload using XSalsa20 stream cipher."""
    # Construct 24-byte nonce from header fields
    nonce = bytes([mctrl, dctrl]) + mac_bytes + bytes([seq_hi, seq_lo])
    nonce += b'\x00' * (24 - len(nonce))

    # The encrypted data is MIC + payload (stream_xor covers both)
    ciphertext = mic + payload

    try:
        plaintext = pysodium.crypto_stream_xor(
            ciphertext, len(ciphertext), nonce, key
        )
        return plaintext[:4], plaintext[4:]  # decrypted_mic, decrypted_payload
    except Exception:
        return None, None


def format_mac(mac_bytes):
    return ":".join(f"{b:02X}" for b in mac_bytes)


def parse_packet_line(line):
    """Parse a sniffer output line into packet components."""
    # Match: [PKT #N t=T] CHAN | len=L | RSSI=R | SNR=S | CRC=C
    pkt_match = re.match(
        r'\[PKT #(\d+)\s+t=(\d+)\]\s+(.+?)\s+\|\s+len=(\d+)\s+\|\s+RSSI=([-\d.]+)\s+\|\s+SNR=([-\d.]+)\s+\|\s+CRC=(\w+)',
        line
    )
    if not pkt_match:
        return None

    return {
        'num': int(pkt_match.group(1)),
        'time_ms': int(pkt_match.group(2)),
        'channel': pkt_match.group(3).strip(),
        'length': int(pkt_match.group(4)),
        'rssi': float(pkt_match.group(5)),
        'snr': float(pkt_match.group(6)),
        'crc': pkt_match.group(7),
    }


def parse_hex_line(line):
    """Parse: HEX: AA BB CC ..."""
    match = re.match(r'\s*HEX:\s+((?:[0-9A-Fa-f]{2}\s*)+)', line)
    if not match:
        return None
    return bytes.fromhex(match.group(1).replace(' ', ''))


def decode_and_print(pkt_info, raw_bytes, key):
    """Decode and pretty-print a SuperLink packet."""
    if len(raw_bytes) < 14:
        return

    mctrl = raw_bytes[0]
    dctrl = raw_bytes[1]
    mac_bytes = raw_bytes[2:8]
    seq_hi = raw_bytes[8]
    seq_lo = raw_bytes[9]
    mic = raw_bytes[10:14]
    payload = raw_bytes[14:]

    mac_str = format_mac(mac_bytes)
    direction, frame_type = DCTRL_INFO.get(dctrl, ("??", "unknown"))

    # Direction arrow and color
    if direction == "UL":
        arrow = f"{C_GREEN}▲ UL{C_RESET}"
        dir_color = C_GREEN
    elif direction == "DL":
        arrow = f"{C_BLUE}▼ DL{C_RESET}"
        dir_color = C_BLUE
    else:
        arrow = f"{C_YELLOW}? ??{C_RESET}"
        dir_color = C_YELLOW

    # Timestamp
    now = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # Header line
    crc_str = f"{C_GREEN}OK{C_RESET}" if pkt_info['crc'] == 'OK' else f"{C_RED}FAIL{C_RESET}"
    print(
        f"{C_DIM}{now}{C_RESET} "
        f"{arrow} "
        f"{C_BOLD}#{pkt_info['num']:>4}{C_RESET} "
        f"{dir_color}{pkt_info['channel']:>20}{C_RESET} "
        f"RSSI={pkt_info['rssi']:>5.0f} "
        f"SNR={pkt_info['snr']:>4.1f} "
        f"CRC={crc_str}"
    )

    # Header details
    print(
        f"  {C_DIM}HDR{C_RESET} "
        f"mctrl={C_CYAN}0x{mctrl:02X}{C_RESET} "
        f"dctrl={C_CYAN}0x{dctrl:02X}{C_RESET} "
        f"mac={C_MAGENTA}{mac_str}{C_RESET} "
        f"seq={C_YELLOW}0x{seq_hi:02X}{seq_lo:02X}{C_RESET} "
        f"mic={mic.hex()}"
    )

    # Decrypt
    if key and payload:
        dec_mic, dec_payload = decrypt_payload(
            mctrl, dctrl, mac_bytes, seq_hi, seq_lo, mic, payload, key
        )
        if dec_payload is not None:
            hex_str = " ".join(f"{b:02X}" for b in dec_payload)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in dec_payload)
            print(
                f"  {C_BOLD}{dir_color}DEC{C_RESET} "
                f"[{len(dec_payload)}B] "
                f"{hex_str}  {C_DIM}{ascii_str}{C_RESET}"
            )
        else:
            print(f"  {C_RED}DEC FAILED{C_RESET}")
    elif payload:
        hex_str = " ".join(f"{b:02X}" for b in payload)
        print(f"  {C_DIM}ENC [{len(payload)}B] {hex_str}{C_RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(description="SuperLink real-time packet decoder")
    parser.add_argument("--port", default="/dev/cu.usbserial-0001",
                        help="Serial port for Heltec sniffer")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--key", type=str, default=None,
                        help="Session key (64 hex chars). Default: last captured key")
    parser.add_argument("--no-decrypt", action="store_true",
                        help="Disable decryption, show raw encrypted payloads")
    parser.add_argument("--cmd", type=str, default="u",
                        help="Initial sniffer command (u=UL, d=DL, a=all, 1-8=park)")
    args = parser.parse_args()

    key = None if args.no_decrypt else (
        bytes.fromhex(args.key) if args.key else DEFAULT_SESSION_KEY
    )

    print(f"{C_BOLD}SuperLink Decoder v0.1{C_RESET}")
    print(f"  Port: {args.port}")
    print(f"  Key:  {'disabled' if not key else key.hex()[:16] + '...'}")
    print()

    try:
        ser = serial.Serial(args.port, args.baud, timeout=0.1)
    except serial.SerialException as e:
        print(f"{C_RED}Cannot open {args.port}: {e}{C_RESET}")
        sys.exit(1)

    # Send initial command
    if args.cmd:
        ser.write(args.cmd.encode())
        time.sleep(0.5)
        ser.read(1024)  # drain response

    print(f"{C_DIM}Listening...{C_RESET}\n")

    current_pkt = None
    raw_bytes = None
    line_buffer = ""

    try:
        while True:
            data = ser.read(256)
            if not data:
                continue

            line_buffer += data.decode("utf-8", errors="replace")

            while "\n" in line_buffer:
                line, line_buffer = line_buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue

                # Try to parse packet header
                pkt = parse_packet_line(line)
                if pkt:
                    # If we had a previous packet waiting for HEX, print it now
                    if current_pkt and raw_bytes:
                        decode_and_print(current_pkt, raw_bytes, key)
                    current_pkt = pkt
                    raw_bytes = None
                    continue

                # Try to parse hex dump
                hex_data = parse_hex_line(line)
                if hex_data and current_pkt:
                    raw_bytes = hex_data
                    # Don't print yet - wait for next packet or timeout
                    # Actually, print immediately since HEX comes right after PKT
                    decode_and_print(current_pkt, raw_bytes, key)
                    current_pkt = None
                    raw_bytes = None
                    continue

    except KeyboardInterrupt:
        print(f"\n{C_DIM}Stopped.{C_RESET}")
    finally:
        ser.close()


if __name__ == "__main__":
    main()
