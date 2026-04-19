"""
DL capture tool for sniffing Ubiquiti gateway pairing responses.

Configures SX1302 in combined UL+DL mode: full 8-channel UL coverage
(125 kHz multi-SF on Radio A) plus one 500 kHz DL service channel
(IF 8 on Radio B). Use this to capture the real Ubiquiti gateway's
0x62 ConnectionRsp during initial pairing.

Usage:
    python -m superlink.capture --dl-channel 11

Workflow:
    1. Factory reset the sensor
    2. Power up Ubiquiti gateway
    3. Run this script with --dl-channel matching the expected DL channel
    4. Watch for UL 0x40 discoveries — note which UL channel they arrive on
    5. UL CH N pairs with DL CH (N+8). If your --dl-channel matches, you'll
       see the gateway's 0x62 response on the DL service channel.
    6. If discoveries only arrive on a different UL channel, restart with
       the matching --dl-channel.
"""

import argparse
import logging
import sys
import time

from .decoder import (
    decrypt_frame, format_mac, parse_frame, DCTRL_TABLE,
)

log = logging.getLogger(__name__)

DEFAULT_PAIRING_KEY = bytes.fromhex(
    "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
)


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
    log.info("=== DL Capture Mode ===")
    log.info("DL CH%d (%.1f MHz, 500 kHz BW) — paired with UL CH%d",
             args.dl_channel, dl_freq / 1e6, paired_ul)
    log.info("UL CH1-8 also active (125 kHz multi-SF on Radio A)")

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
                if not pkt.crc_ok:
                    continue

                frame = parse_frame(pkt.payload)
                if frame is None:
                    continue

                if pkt.dl_channel:
                    # === DL frame on service channel ===
                    dl_count += 1
                    _, ftype = DCTRL_TABLE.get(frame.dctrl, ("DL", "unknown"))

                    # Try decryption with pairing key, counter=0
                    frame = decrypt_frame(
                        frame, DEFAULT_PAIRING_KEY,
                        ul_counter_offset=frame.seq_hi,
                    )

                    log.info("*** DL CH%d *** dctrl=0x%02X (%s) mac=%s "
                             "seq=%02X.%02X rssi=%.0f snr=%.1f size=%d",
                             pkt.dl_channel, frame.dctrl, ftype,
                             format_mac(frame.mac),
                             frame.seq_hi, frame.seq_lo,
                             pkt.rssi, pkt.snr, len(pkt.payload))
                    log.info("  RAW: %s", pkt.payload.hex())
                    if frame.mic:
                        log.info("  MIC: %s", frame.mic.hex())
                    if frame.payload:
                        log.info("  PAYLOAD (%dB): %s",
                                 len(frame.payload), frame.payload.hex())
                        # Extract pubkey from 0x62 ConnectionRsp
                        if frame.dctrl == 0x62 and len(frame.payload) >= 49:
                            log.info("  inner_type: 0x%02X 0x%02X",
                                     frame.payload[0], frame.payload[1])
                            pubkey = frame.payload[17:49]
                            log.info("  GW PUBKEY: %s", pubkey.hex())
                            log.info("  header[2:17]: %s",
                                     frame.payload[2:17].hex())
                    print()  # blank line for readability

                else:
                    # === UL frame ===
                    ul_count += 1

                    if frame.dctrl == 0x40:
                        # Discovery — always show
                        frame = decrypt_frame(
                            frame, DEFAULT_PAIRING_KEY,
                            ul_counter_offset=frame.seq_hi,
                        )
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
                        # ConnectionChallenge — means sensor accepted a 0x53
                        frame = decrypt_frame(
                            frame, DEFAULT_PAIRING_KEY,
                            ul_counter_offset=frame.seq_hi,
                        )
                        log.info(
                            "UL CH%d  0x42 CONN_CHALLENGE mac=%s "
                            "seq=%02X.%02X rssi=%.0f size=%d",
                            pkt.ul_channel, format_mac(frame.mac),
                            frame.seq_hi, frame.seq_lo,
                            pkt.rssi, len(pkt.payload),
                        )
                        if frame.payload and len(frame.payload) >= 49:
                            pubkey = frame.payload[17:49]
                            log.info("  SENSOR PUBKEY: %s", pubkey.hex())
                        log.info("  Sensor accepted a 0x62! Pairing advancing.")
                        print()

                    elif frame.dctrl in (0x44, 0x54) and args.verbose:
                        log.info(
                            "UL CH%d  dctrl=0x%02X mac=%s seq=%02X.%02X "
                            "rssi=%.0f size=%d",
                            pkt.ul_channel, frame.dctrl,
                            format_mac(frame.mac),
                            frame.seq_hi, frame.seq_lo,
                            pkt.rssi, len(pkt.payload),
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
