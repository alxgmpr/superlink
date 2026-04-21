#!/usr/bin/env python3
"""
Robust serial reader for the Heltec SuperLink sniffer.

- Auto-reconnects on disconnect/IO error
- Streams everything to stdout AND a durable JSONL log
- Optional one-shot or periodic setup command (e.g. park on DL CH N)
- Tries a small list of candidate serial ports if the primary is busy

Typical use:
    # Park on DL CH9 and log everything
    python reader.py --port /dev/cu.usbserial-0001 --cmd '!'

    # DL-only scan mode
    python reader.py --cmd d --label heltec-dlscan

Exit with Ctrl+C. Logs to ~/superlink_heltec_<ts>.jsonl unless --out is given.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

try:
    import serial  # pyserial
except ImportError:
    sys.stderr.write("pyserial not installed. Run: pip install pyserial\n")
    sys.exit(2)


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_candidate_ports(preferred: str | None) -> list[str]:
    candidates: list[str] = []
    if preferred:
        candidates.append(preferred)
    # macOS Heltec CP210x USB-UART device names
    candidates += sorted(glob.glob("/dev/cu.usbserial-*"))
    candidates += sorted(glob.glob("/dev/tty.usbserial-*"))
    # Linux
    candidates += sorted(glob.glob("/dev/ttyUSB*"))
    # Dedup preserving order
    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def try_open(port: str, baud: int) -> serial.Serial | None:
    try:
        ser = serial.Serial(port, baudrate=baud, timeout=0.5, write_timeout=1.0)
        return ser
    except (serial.SerialException, OSError) as e:
        sys.stderr.write(f"[reader] open {port} failed: {e}\n")
        return None


def parse_pkt_line(line: str) -> dict | None:
    """Extract a packet event from the Heltec log."""
    m = re.match(
        r"\[PKT\s+#(?P<n>\d+)\s+t=(?P<t>\d+)\]\s+(?P<ch>[^|]+?)"
        r"\s*\|\s*len=(?P<len>\d+)\s*\|\s*RSSI=(?P<rssi>[-\d.]+)"
        r"\s*\|\s*SNR=(?P<snr>[-\d.]+)\s*\|\s*CRC=(?P<crc>OK|FAIL)",
        line,
    )
    if not m:
        return None
    return {
        "event": "pkt_header",
        "n": int(m["n"]),
        "t_ms": int(m["t"]),
        "channel": m["ch"].strip(),
        "len": int(m["len"]),
        "rssi": float(m["rssi"]),
        "snr": float(m["snr"]),
        "crc_ok": m["crc"] == "OK",
    }


def parse_hex_line(line: str) -> dict | None:
    m = re.match(r"\s*HEX:\s*([0-9A-Fa-f ]+)", line)
    if m:
        return {"event": "hex", "hex": m.group(1).replace(" ", "").lower()}
    m = re.match(r"\s*HDR:\s*(.+)", line)
    if m:
        return {"event": "hdr", "hdr": m.group(1)}
    m = re.match(r"\s*PAY:\s*(.+)", line)
    if m:
        return {"event": "pay", "pay": m.group(1)}
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--port", default=None, help="Preferred serial port")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--cmd", default=None,
                    help="One-shot setup command to send after connect "
                         "(e.g. 'd' for DL scan, '!' for DL CH9 park)")
    ap.add_argument("--out", default=None, help="JSONL output path")
    ap.add_argument("--label", default="heltec",
                    help="Label stamped on every JSONL record")
    ap.add_argument("--quiet", action="store_true",
                    help="Don't echo serial lines to stdout")
    args = ap.parse_args()

    out_path = args.out or os.path.expanduser(
        f"~/superlink_heltec_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    )
    out_fp = open(out_path, "a", buffering=1)

    def emit(record: dict) -> None:
        record["ts"] = iso_now()
        record["label"] = args.label
        out_fp.write(json.dumps(record) + "\n")
        out_fp.flush()
        try:
            os.fsync(out_fp.fileno())
        except OSError:
            pass

    sys.stderr.write(f"[reader] durable log: {out_path}\n")
    emit({"event": "reader_start", "label": args.label, "cmd": args.cmd})

    ser: serial.Serial | None = None
    buf = b""
    last_cmd_time = 0.0

    try:
        while True:
            if ser is None:
                for port in find_candidate_ports(args.port):
                    ser = try_open(port, args.baud)
                    if ser is not None:
                        sys.stderr.write(f"[reader] connected: {port}\n")
                        emit({"event": "connect", "port": port})
                        buf = b""
                        last_cmd_time = 0.0
                        break
                if ser is None:
                    time.sleep(1.0)
                    continue

            # Send setup command shortly after connect + repeat every 30s
            # in case the device reset.
            if args.cmd and (time.monotonic() - last_cmd_time) > 30:
                try:
                    # Small delay so the device's serial is ready
                    time.sleep(0.3)
                    ser.write(args.cmd.encode())
                    ser.flush()
                    emit({"event": "cmd_sent", "cmd": args.cmd})
                    last_cmd_time = time.monotonic()
                except (serial.SerialException, OSError) as e:
                    sys.stderr.write(f"[reader] cmd write failed: {e}\n")

            try:
                chunk = ser.read(4096)
            except (serial.SerialException, OSError) as e:
                sys.stderr.write(f"[reader] read error, reconnecting: {e}\n")
                emit({"event": "disconnect", "reason": str(e)})
                try:
                    ser.close()
                except Exception:
                    pass
                ser = None
                time.sleep(1.0)
                continue

            if not chunk:
                continue

            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", errors="replace").rstrip("\r")
                if not args.quiet:
                    sys.stdout.write(text + "\n")
                    sys.stdout.flush()

                rec = parse_pkt_line(text)
                if rec is None:
                    rec = parse_hex_line(text)
                if rec is None:
                    rec = {"event": "line", "text": text}
                emit(rec)

    except KeyboardInterrupt:
        sys.stderr.write("\n[reader] stopped by user\n")
        emit({"event": "reader_stop"})
        return 0
    finally:
        if ser is not None:
            try:
                ser.close()
            except Exception:
                pass
        out_fp.close()


if __name__ == "__main__":
    sys.exit(main())
