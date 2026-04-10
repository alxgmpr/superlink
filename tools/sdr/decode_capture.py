#!/usr/bin/env python3
"""
SuperLink UL offline decoder
Processes RTL-SDR IQ capture, decodes all 8 UL channels (915.6-917.0 MHz)

Usage:
    python3 decode_capture.py [iq_file]
    Default iq_file: /tmp/superlink_ul.iq
"""

import numpy as np
import math
import os
import sys
from gnuradio import gr, blocks
from gnuradio import filter as gr_filter
from gnuradio import lora_sdr

# --- Capture parameters ---
SAMPLE_RATE  = 2_400_000
CENTER_FREQ  = 916_300_000   # Hz

# --- SuperLink UL radio parameters (confirmed from firmware RE + OTA) ---
SF           = 5
BW           = 125_000
CR           = 1             # 4/5
HAS_CRC      = True          # LoRa PHY CRC enabled on SX1262
IMPL_HEAD    = False         # Explicit header mode
SYNC_WORD    = [0x12]        # [18] — private LoRa sync word
PREAMBLE_LEN = 12
MAX_PAY_LEN  = 255

# --- Resampling: 2.4 MSPS → 500 kSPS (os_factor=4 for SF5) ---
# 2400000 * 5 / 24 = 500000
RESAMP_INTERP = 5
RESAMP_DECIM  = 24
DECODER_RATE  = SAMPLE_RATE * RESAMP_INTERP // RESAMP_DECIM  # 500000

# --- 8 UL channels: 915.6 MHz + n*200 kHz ---
UL_FREQS = [915_600_000 + i * 200_000 for i in range(8)]


def convert_iq(iq_file: str, cf_file: str):
    """Convert rtl_sdr uint8 interleaved IQ → complex float32 binary."""
    if os.path.exists(cf_file):
        print(f"[convert] Using cached {cf_file}")
        return
    print(f"[convert] {iq_file} → {cf_file} ...")
    raw = np.fromfile(iq_file, dtype=np.uint8)
    i_data = (raw[0::2].astype(np.float32) - 127.5) / 127.5
    q_data = (raw[1::2].astype(np.float32) - 127.5) / 127.5
    cx = (i_data + 1j * q_data).astype(np.complex64)
    cx.tofile(cf_file)
    size_mb = os.path.getsize(cf_file) / 1e6
    print(f"[convert] {len(cx):,} samples saved ({size_mb:.1f} MB)")


class ChannelDecoder(gr.top_block):
    """
    Single-channel LoRa decoder flowgraph using individual gr-lora_sdr blocks.
    We bypass lora_sdr_lora_rx because it hardcodes preamble_len=8; SuperLink uses 12.

    Chain:
      file_source → rotator → rational_resampler
        → frame_sync → fft_demod → gray_mapping → deinterleaver
        → hamming_dec → header_decoder → dewhitening → crc_verif → null_sink
    Message feedback: header_decoder.frame_info → frame_sync.frame_info
    """
    def __init__(self, cf_file: str, channel_idx: int):
        gr.top_block.__init__(self, f"SuperLink UL CH{channel_idx+1}")

        ch_freq     = UL_FREQS[channel_idx]
        freq_offset = ch_freq - CENTER_FREQ
        os_factor   = DECODER_RATE // BW   # 4

        # IQ file source
        src = blocks.file_source(gr.sizeof_gr_complex, cf_file, repeat=False)

        # Frequency-shift to baseband
        rotator = blocks.rotator_cc(-2.0 * math.pi * freq_offset / SAMPLE_RATE)

        # Rational resample: 2.4 MSPS → 500 kSPS
        resampler = gr_filter.rational_resampler_ccf(
            interpolation=RESAMP_INTERP,
            decimation=RESAMP_DECIM,
            taps=[],
            fractional_bw=0.4,
        )

        # gr-lora_sdr demodulation chain (individual blocks)
        frame_sync   = lora_sdr.frame_sync(ch_freq, BW, SF, IMPL_HEAD,
                                            SYNC_WORD, os_factor, PREAMBLE_LEN)
        fft_demod    = lora_sdr.fft_demod(soft_decoding=False, max_log_approx=True)
        gray_map     = lora_sdr.gray_mapping(soft_decoding=False)
        deinterleave = lora_sdr.deinterleaver(soft_decoding=False)
        hamming      = lora_sdr.hamming_dec(soft_decoding=False)
        hdr_decode   = lora_sdr.header_decoder(IMPL_HEAD, CR, MAX_PAY_LEN,
                                                HAS_CRC, 0, print_header=True)
        dewhiten     = lora_sdr.dewhitening()
        crc_check    = lora_sdr.crc_verif(print_rx_msg=True, output_crc_check=False)
        sink         = blocks.null_sink(gr.sizeof_char)

        # Stream chain
        self.connect(src, rotator, resampler, frame_sync,
                     fft_demod, gray_map, deinterleave,
                     hamming, hdr_decode, dewhiten, crc_check, sink)

        # Message feedback: header info → frame sync
        self.msg_connect(hdr_decode, "frame_info", frame_sync, "frame_info")


def decode_all_channels(iq_file: str):
    cf_file = iq_file.replace(".iq", "_cf32.bin")
    if not iq_file.endswith(".iq"):
        cf_file = iq_file + "_cf32.bin"

    convert_iq(iq_file, cf_file)

    for ch_idx in range(8):
        ch_freq = UL_FREQS[ch_idx]
        offset  = (ch_freq - CENTER_FREQ) / 1000
        print(f"\n{'='*60}")
        print(f"  UL CH{ch_idx+1}  {ch_freq/1e6:.1f} MHz  (offset {offset:+.0f} kHz from center)")
        print(f"{'='*60}")
        sys.stdout.flush()

        tb = ChannelDecoder(cf_file, ch_idx)
        tb.run()
        del tb

    print("\n[done]")


if __name__ == "__main__":
    iq_file = sys.argv[1] if len(sys.argv) > 1 else "/tmp/superlink_ul.iq"
    if not os.path.exists(iq_file):
        print(f"ERROR: file not found: {iq_file}")
        sys.exit(1)
    decode_all_channels(iq_file)
