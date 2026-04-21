"""
DL capture tool for sniffing Ubiquiti gateway pairing responses.

Configures SX1302 in combined UL+DL mode: full 8-channel UL coverage
(125 kHz multi-SF on Radio A) plus one 500 kHz DL service channel
(IF 8 on Radio B). Use this to capture the real Ubiquiti gateway's
0x62 ConnectionRsp and 0x62 ChallengeRsp during pairing.

Always writes a machine-parseable line to --out (defaults to
~/capture_<dl>_<ts>.jsonl) so frames survive crashes.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

from .decoder import (
    decrypt_frame, format_mac, parse_frame, DCTRL_TABLE,
)

log = logging.getLogger(__name__)

DEFAULT_PAIRING_KEY = bytes.fromhex(
    "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
)


def _inner_type_label(payload: bytes) -> str:
    if len(payload) < 2:
        return "?"
    if payload[0] != 0x01:
        return f"outer=0x{payload[0]:02x}"
    return {
        0x01: "ConnRsp",
        0x02: "ConnChallenge",
        0x03: "ChallengeRsp",
    }.get(payload[1], f"inner=0x{payload[1]:02x}")


def main():
    parser = argparse.ArgumentParser(
        description="Capture DL frames from Ubiquiti gateway during pairing"
    )
    parser.add_argument(
        "--dl-channel", type=int, required=True, metavar="CH",
        help="DL channel to monitor (9-16). CH9 pairs with UL CH1, etc.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show all UL frames, not just discoveries and challenges",
    )
    parser.add_argument(
        "--out", metavar="PATH",
        help="JSONL output file (default: ~/capture_dl<N>_<ts>.jsonl)",
    )
    parser.add_argument(
        "--label", default="",
        help="Optional label added to JSONL records (e.g. board name)",
    )
    args = parser.parse_args()

    if not (9 <= args.dl_channel <= 16):
        print(f"Error: --dl-channel must be 9-16, got {args.dl_channel}",
              file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    from .hal import SX1302, DL_FREQ_HZ

    paired_ul = args.dl_channel - 8  # DL CH9 ↔ UL CH1, etc.
    dl_freq = DL_FREQ_HZ[args.dl_channel - 9]

    # Durable JSONL output
    out_path = args.out or os.path.expanduser(
        f"~/capture_dl{args.dl_channel}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    )
    out_fp = open(out_path, "a", buffering=1)

    def emit(record: dict) -> None:
        record["ts"] = datetime.now(timezone.utc).isoformat()
        record["label"] = args.label
        record["dl_channel_monitored"] = args.dl_channel
        out_fp.write(json.dumps(record) + "\n")
        out_fp.flush()
        try:
            os.fsync(out_fp.fileno())
        except OSError:
            pass

    log.info("=== DL Capture Mode ===")
    log.info("DL CH%d (%.1f MHz, 500 kHz BW) — paired with UL CH%d",
             args.dl_channel, dl_freq / 1e6, paired_ul)
    log.info("UL CH1-8 also active (125 kHz multi-SF on Radio A)")
    log.info("Durable log: %s", out_path)
    if args.label:
        log.info("Label: %s", args.label)

    hal = None
    ul_count = 0
    dl_count = 0
    ul_ch_seen = set()
    try:
        hal = SX1302()
        hal.start(dl_channel=args.dl_channel)
        log.info("Concentrator started (HAL %s)", hal.version())
        log.info("Listening... Ctrl+C to stop\n")

        while True:
            for pkt in hal.receive():
                # Persist EVERY packet (including CRC fails) — evidence first.
                frame = parse_frame(pkt.payload)

                base_record = {
                    "direction": "DL" if pkt.dl_channel else "UL",
                    "ul_channel": pkt.ul_channel,
                    "dl_channel": pkt.dl_channel,
                    "freq_hz": pkt.freq_hz,
                    "rssi": pkt.rssi,
                    "snr": pkt.snr,
                    "crc_ok": pkt.crc_ok,
                    "timestamp_us": pkt.timestamp_us,
                    "size": len(pkt.payload),
                    "raw_hex": pkt.payload.hex(),
                }

                if not pkt.crc_ok or frame is None:
                    base_record["note"] = "crc_bad" if not pkt.crc_ok else "short"
                    emit(base_record)
                    continue

                frame = decrypt_frame(
                    frame, DEFAULT_PAIRING_KEY,
                    ul_counter_offset=frame.seq_hi,
                )
                _, ftype = DCTRL_TABLE.get(frame.dctrl, ("?", "unknown"))
                inner_label = _inner_type_label(frame.payload or b"")

                base_record.update({
                    "mctrl": frame.mctrl,
                    "dctrl": frame.dctrl,
                    "dctrl_type": ftype,
                    "mac": format_mac(frame.mac),
                    "seq_hi": frame.seq_hi,
                    "seq_lo": frame.seq_lo,
                    "mic_hex": frame.mic.hex() if frame.mic else None,
                    "payload_hex": frame.payload.hex() if frame.payload else None,
                    "payload_len": len(frame.payload) if frame.payload else 0,
                    "inner_label": inner_label,
                })

                if pkt.dl_channel:
                    # === DL frame on service channel ===
                    dl_count += 1

                    # Pubkey offsets per corrected RE:
                    #   0x62 ConnRsp (01 01): pubkey at [2:34]
                    #   0x62 ChallengeRsp (01 03): pubkey at [2:34]
                    if (frame.dctrl == 0x62 and frame.payload
                            and len(frame.payload) >= 34
                            and frame.payload[:2] in (b"\x01\x01", b"\x01\x03")):
                        base_record["gw_pubkey_hex"] = frame.payload[2:34].hex()
                        if len(frame.payload) >= 41:
                            base_record["tail_hex"] = frame.payload[34:41].hex()

                    emit(base_record)

                    log.info("*** DL CH%d *** dctrl=0x%02X (%s) %s mac=%s "
                             "seq=%02X.%02X rssi=%.0f snr=%.1f size=%d",
                             pkt.dl_channel, frame.dctrl, ftype, inner_label,
                             format_mac(frame.mac),
                             frame.seq_hi, frame.seq_lo,
                             pkt.rssi, pkt.snr, len(pkt.payload))
                    log.info("  RAW: %s", pkt.payload.hex())
                    if frame.mic:
                        log.info("  MIC: %s", frame.mic.hex())
                    if frame.payload:
                        log.info("  PAYLOAD (%dB): %s",
                                 len(frame.payload), frame.payload.hex())
                        if frame.dctrl == 0x62 and len(frame.payload) >= 34:
                            log.info("  inner: %02X %02X  (%s)",
                                     frame.payload[0], frame.payload[1],
                                     inner_label)
                            log.info("  GW PUBKEY [2:34]: %s",
                                     frame.payload[2:34].hex())
                            if len(frame.payload) >= 41:
                                log.info("  TAIL [34:41]: %s",
                                         frame.payload[34:41].hex())
                            if len(frame.payload) > 41:
                                log.info("  EXTRA [41:]: %s",
                                         frame.payload[41:].hex())
                            if frame.payload[:2] == b"\x01\x03":
                                log.info(
                                    "  ============================")
                                log.info(
                                    "  *** GOT CHALLENGERSP! ***")
                                log.info(
                                    "  ============================")
                    print()  # blank line for readability

                else:
                    # === UL frame ===
                    ul_count += 1
                    emit(base_record)

                    if frame.dctrl == 0x40:
                        ul_ch_seen.add(pkt.ul_channel)
                        on_target = pkt.ul_channel == paired_ul
                        marker = " <<<" if on_target else ""
                        log.info(
                            "UL CH%d  0x40 DISCOVERY mac=%s seq=%02X.%02X "
                            "rssi=%.0f payload=%s%s",
                            pkt.ul_channel, format_mac(frame.mac),
                            frame.seq_hi, frame.seq_lo,
                            pkt.rssi,
                            frame.payload.hex() if frame.payload else "?",
                            marker,
                        )
                        if on_target:
                            log.info("  ^ This UL channel pairs with our "
                                     "DL CH%d — watch for DL response!",
                                     args.dl_channel)

                    elif frame.dctrl == 0x42:
                        # 0x42 pubkey at [13:45] per corrected RE
                        raw_hex = pkt.payload.hex()
                        dec_hex = frame.payload.hex() if frame.payload else "<decrypt_failed>"
                        log.info(
                            "UL CH%d  0x42 CONN_CHALLENGE mac=%s seq=%02X.%02X "
                            "rssi=%.0f raw_len=%d dec_len=%d",
                            pkt.ul_channel, format_mac(frame.mac),
                            frame.seq_hi, frame.seq_lo,
                            pkt.rssi, len(pkt.payload),
                            len(frame.payload) if frame.payload else 0,
                        )
                        log.info("  RAW 0x42: %s", raw_hex)
                        log.info("  DEC 0x42: %s", dec_hex)
                        if frame.payload and len(frame.payload) >= 45:
                            log.info("  SENSOR PUBKEY [13:45]: %s",
                                     frame.payload[13:45].hex())
                            log.info("  MARKER   [45:49]: %s",
                                     frame.payload[45:49].hex()
                                     if len(frame.payload) >= 49 else "<missing>")
                        print()

                    elif frame.dctrl in (0x44, 0x54, 0x74):
                        log.info(
                            "UL CH%d  dctrl=0x%02X (%s) mac=%s seq=%02X.%02X "
                            "rssi=%.0f size=%d",
                            pkt.ul_channel, frame.dctrl, ftype,
                            format_mac(frame.mac),
                            frame.seq_hi, frame.seq_lo,
                            pkt.rssi, len(pkt.payload),
                        )
                    elif args.verbose:
                        log.debug(
                            "UL CH%d  dctrl=0x%02X mac=%s seq=%02X.%02X",
                            pkt.ul_channel, frame.dctrl,
                            format_mac(frame.mac),
                            frame.seq_hi, frame.seq_lo,
                        )

            time.sleep(0.01)

    except KeyboardInterrupt:
        print()
        log.info("Stopped. UL=%d DL=%d frames captured.", ul_count, dl_count)
        if ul_ch_seen:
            log.info("UL channels seen: %s",
                     ", ".join(f"CH{ch}" for ch in sorted(ul_ch_seen)))
            if paired_ul not in ul_ch_seen and ul_ch_seen:
                suggest = min(ul_ch_seen) + 8
                log.info("Hint: sensor used UL CH%s — try --dl-channel %d",
                         ",".join(str(ch) for ch in sorted(ul_ch_seen)),
                         suggest)
    finally:
        if hal:
            hal.stop()


if __name__ == "__main__":
    main()
