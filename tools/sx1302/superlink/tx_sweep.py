"""
TX timing sweep — cycle through different delays and IQ settings
on each discovery to find the sensor's RX window.

Tries: immediate, 100ms, 500ms, 1s, 2s, 4s — each with normal and inverted IQ.
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

# Delays to sweep (microseconds), with IQ inversion flag
SWEEP = [
    (0,       False, 'immediate, normal IQ'),
    (0,       True,  'immediate, inverted IQ'),
    (100_000, False, '100ms, normal IQ'),
    (100_000, True,  '100ms, inverted IQ'),
    (500_000, False, '500ms, normal IQ'),
    (500_000, True,  '500ms, inverted IQ'),
    (1_000_000, False, '1s, normal IQ'),
    (1_000_000, True,  '1s, inverted IQ'),
    (2_000_000, False, '2s, normal IQ'),
    (2_000_000, True,  '2s, inverted IQ'),
    (4_000_000, False, '4s, normal IQ'),
    (4_000_000, True,  '4s, inverted IQ'),
]

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s.%(msecs)03d %(message)s',
        datefmt='%H:%M:%S',
    )

    privkey, pubkey = generate_keypair()
    tx_seq = 0
    sweep_idx = 0

    hal = SX1302()
    try:
        log.info('Starting concentrator...')
        hal.start()
        log.info('HAL %s — sweep mode, %d configs to try', hal.version(), len(SWEEP))
        log.info('Waiting for 0x40 discoveries...\n')

        while True:
            for pkt in hal.receive():
                if not pkt.crc_ok:
                    continue
                frame = parse_frame(pkt.payload)
                if frame is None:
                    continue

                if frame.dctrl == 0x40:
                    # Discovery
                    dec = decrypt_frame(frame, PAIRING_KEY, ul_counter_offset=frame.seq_hi)
                    log.info('DISCOVERY from %s ch=%d seq=%02X payload=%s',
                             format_mac(frame.mac), pkt.ul_channel,
                             frame.seq_hi,
                             dec.payload.hex() if dec.payload else '?')

                    if not (1 <= pkt.ul_channel <= 8):
                        log.info('  skip: no UL channel')
                        continue

                    delay_us, invert, desc = SWEEP[sweep_idx % len(SWEEP)]
                    sweep_idx += 1
                    tx_seq = (tx_seq + 1) & 0xFF

                    # Build 0x62 ConnectionRsp
                    captured_inner_hdr = bytes.fromhex('74ad9482f05344')
                    inner_payload = b'\x01\x01' + captured_inner_hdr + pubkey

                    header = bytes([0xE0, 0x62]) + frame.mac + bytes([tx_seq, 0x00])
                    mic = compute_mic(header, inner_payload)
                    tx_frame = build_frame(
                        0xE0, 0x62, frame.mac, tx_seq, 0x00,
                        mic, inner_payload, PAIRING_KEY, counter=0,
                    )

                    dl_freq = DL_FREQ_HZ[pkt.ul_channel - 1]
                    tx_ts = (pkt.timestamp_us + delay_us) & 0xFFFFFFFF if delay_us else 0

                    hal.send(dl_freq, tx_frame, bandwidth=BW_500KHZ,
                             tx_timestamp_us=tx_ts, invert_pol=invert)

                    mode = f'scheduled +{delay_us}us' if tx_ts else 'immediate'
                    log.info('  TX [%d/%d] %s on %.1f MHz (%d bytes)',
                             sweep_idx, len(SWEEP), desc, dl_freq / 1e6, len(tx_frame))
                    log.info('  mode=%s ts=%d', mode, tx_ts)
                    print(flush=True)

                elif frame.dctrl == 0x42:
                    # ConnectionChallenge — SUCCESS!
                    dec = decrypt_frame(frame, PAIRING_KEY, ul_counter_offset=frame.seq_hi)
                    log.info('*** 0x42 CONNECTION CHALLENGE from %s ***',
                             format_mac(frame.mac))
                    log.info('  seq=%02X.%02X payload=%s',
                             frame.seq_hi, frame.seq_lo,
                             dec.payload.hex() if dec.payload else '?')
                    if dec.payload and len(dec.payload) >= 49:
                        log.info('  SENSOR PUBKEY: %s', dec.payload[17:49].hex())
                    prev_idx = (sweep_idx - 1) % len(SWEEP)
                    log.info('  WINNING CONFIG: %s', SWEEP[prev_idx][2])
                    log.info('  delay=%d us, invert=%s',
                             SWEEP[prev_idx][0], SWEEP[prev_idx][1])
                    print(flush=True)

            time.sleep(0.01)

    except KeyboardInterrupt:
        log.info('Stopped after %d TX attempts.', sweep_idx)
    finally:
        hal.stop()


if __name__ == '__main__':
    main()
