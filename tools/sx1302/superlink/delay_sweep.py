"""
TX delay sweep — try different RX window delays to find the sensor's window.

Cycles through delays from 500ms to 1500ms in 100ms steps.
Each discovery gets a different delay. Repeats the cycle.
"""

import logging
import sys
import time

sys.path.insert(0, '.')
from superlink.crypto import generate_keypair
from superlink.decoder import (
    build_frame, compute_mic, decrypt_frame, format_mac, parse_frame,
)
from superlink.hal import SX1302, BW_500KHZ, DL_FREQ_HZ

log = logging.getLogger(__name__)

PAIRING_KEY = bytes.fromhex(
    '47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe'
)

# Delays to sweep (microseconds) — all normal IQ (confirmed from firmware RE)
DELAYS = [
    500_000, 600_000, 700_000, 800_000, 900_000,
    1_000_000, 1_100_000, 1_200_000, 1_300_000, 1_400_000, 1_500_000,
]


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s.%(msecs)03d %(message)s',
        datefmt='%H:%M:%S',
        stream=sys.stdout,
    )

    privkey, pubkey = generate_keypair()
    tx_seq = 0
    sweep_idx = 0

    hal = SX1302()
    try:
        log.info('Starting concentrator (TX on Radio B / rf_chain 1)...')
        hal.start(tx_rf_chain=1)
        log.info('HAL %s — delay sweep, %d delays to cycle', hal.version(), len(DELAYS))
        log.info('Delays (ms): %s', ', '.join(str(d // 1000) for d in DELAYS))
        log.info('Waiting for 0x40 discoveries...\n')

        while True:
            for pkt in hal.receive():
                if not pkt.crc_ok:
                    continue
                frame = parse_frame(pkt.payload)
                if frame is None:
                    continue

                if frame.dctrl == 0x40:
                    dec = decrypt_frame(frame, PAIRING_KEY, ul_counter_offset=frame.seq_hi)
                    log.info('DISCOVERY from %s ch=%d seq=%02X',
                             format_mac(frame.mac), pkt.ul_channel, frame.seq_hi)

                    if not (1 <= pkt.ul_channel <= 8):
                        continue

                    delay_us = DELAYS[sweep_idx % len(DELAYS)]
                    sweep_idx += 1
                    tx_seq = (tx_seq + 1) & 0xFF

                    # Build 0x62 ConnRsp (confirmed format from real gateway capture)
                    inner_hdr = bytes.fromhex('74ad9482f05344')
                    inner_payload = b'\x01\x01' + inner_hdr + pubkey

                    header = bytes([0xE0, 0x62]) + frame.mac + bytes([tx_seq, 0x00])
                    mic = compute_mic(header, inner_payload)
                    tx_frame = build_frame(
                        0xE0, 0x62, frame.mac, tx_seq, 0x00,
                        mic, inner_payload, PAIRING_KEY, counter=0,
                    )

                    dl_freq = DL_FREQ_HZ[pkt.ul_channel - 1]
                    tx_ts = (pkt.timestamp_us + delay_us) & 0xFFFFFFFF

                    hal.send(dl_freq, tx_frame, rf_power=24,
                             bandwidth=BW_500KHZ,
                             tx_timestamp_us=tx_ts, invert_pol=False)

                    log.info('  TX [%d] delay=%dms on %.1f MHz (%d bytes) ts=%d',
                             sweep_idx, delay_us // 1000, dl_freq / 1e6,
                             len(tx_frame), tx_ts)

                elif frame.dctrl == 0x42:
                    dec = decrypt_frame(frame, PAIRING_KEY, ul_counter_offset=frame.seq_hi)
                    log.info('*** 0x42 CONNECTION CHALLENGE from %s ***',
                             format_mac(frame.mac))
                    log.info('  seq=%02X.%02X size=%d',
                             frame.seq_hi, frame.seq_lo, len(pkt.payload))
                    if dec.payload and len(dec.payload) >= 49:
                        log.info('  SENSOR PUBKEY: %s', dec.payload[17:49].hex())
                    prev = DELAYS[(sweep_idx - 1) % len(DELAYS)]
                    log.info('  LAST TX DELAY: %dms', prev // 1000)
                    print(flush=True)

            time.sleep(0.01)

    except KeyboardInterrupt:
        log.info('Stopped after %d TX attempts.', sweep_idx)
    finally:
        hal.stop()


if __name__ == '__main__':
    main()
