#!/usr/bin/env python3
"""
Simultaneous RTL-SDR + Heltec sniffer capture for LoRa SF5 decoder calibration.

Mode 1 - CAPTURE: Run both devices, log sniffer packets alongside IQ capture.
    python3 calibrate_capture.py capture --port /dev/cu.usbserial-0001 --ch 6

Mode 2 - CALIBRATE: Post-process to determine correct LoRa decode chain.
    python3 calibrate_capture.py calibrate --iq capture.iq --log capture.log

The calibration uses known packet bytes (from Heltec hardware decoder) as ground
truth to determine the correct gray/deinterleave/hamming conventions for SF5.
"""

import argparse
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np

# ── SuperLink LoRa parameters ──
SF = 5
N = 1 << SF  # 32
BW = 125_000
SAMPLE_RATE = 2_400_000
CENTER_FREQ = 916_300_000
UL_CHANNELS = [915_600_000 + i * 200_000 for i in range(8)]
SYNC_BYTE = 0x12
NET_ID1 = ((SYNC_BYTE >> 4) & 0xF) << 3  # 8
NET_ID2 = (SYNC_BYTE & 0xF) << 3         # 16
PREAMBLE_LEN = 12

INTERP, DECIM = 5, 24
DECODER_RATE = SAMPLE_RATE * INTERP // DECIM  # 500 kSPS
OS = DECODER_RATE // BW  # 4
N_OS = N * OS  # 128 samples/symbol at decoder rate


# ════════════════════════════════════════════════════════════════
#  LoRa PHY encode chain (for computing ground truth symbols)
# ════════════════════════════════════════════════════════════════

def compute_header_nibbles(payload_len, has_crc=True, cr=1):
    """Compute the 5 LoRa header nibbles for given parameters."""
    n0 = (payload_len >> 4) & 0xF
    n1 = payload_len & 0xF
    n2 = ((cr & 0x7) << 1) | (1 if has_crc else 0)
    # Header checksum (from header_decoder_impl.cc)
    i = [n0, n1, n2]
    c4 = ((i[0]>>3)&1) ^ ((i[0]>>2)&1) ^ ((i[0]>>1)&1) ^ (i[0]&1)
    c3 = ((i[0]>>3)&1) ^ ((i[1]>>3)&1) ^ ((i[1]>>2)&1) ^ ((i[1]>>1)&1) ^ (i[2]&1)
    c2 = ((i[0]>>2)&1) ^ ((i[1]>>3)&1) ^ (i[1]&1) ^ ((i[2]>>3)&1) ^ ((i[2]>>1)&1)
    c1 = ((i[0]>>1)&1) ^ ((i[1]>>2)&1) ^ (i[1]&1) ^ ((i[2]>>2)&1) ^ ((i[2]>>1)&1) ^ (i[2]&1)
    c0 = (i[0]&1) ^ ((i[1]>>1)&1) ^ ((i[2]>>3)&1) ^ ((i[2]>>2)&1) ^ ((i[2]>>1)&1) ^ (i[2]&1)
    n3 = c4 & 1  # only bit 0 used; upper 3 bits = 0
    n4 = (c3 << 3) | (c2 << 2) | (c1 << 1) | c0
    return [n0, n1, n2, n3, n4]


def hamming_encode_84(nibble):
    """Encode 4-bit nibble to 8-bit Hamming(8,4) codeword.
    Parity bits: p0=d0^d1^d2, p1=d1^d2^d3, p2=d0^d1^d3, p3=d0^d2^d3
    Codeword: [d0 d1 d2 d3 p0 p1 p2 p3] (MSB first in 8-bit value)
    But data nibble in gr-lora_sdr is REVERSED: {cw[3],cw[2],cw[1],cw[0]}
    So we need to account for the bit reversal."""
    # LUT from hamming_dec_impl.cc
    cw_LUT = [0, 23, 45, 58, 78, 89, 99, 116, 139, 156, 166, 177, 197, 210, 232, 255]
    # The nibble→LUT index mapping accounts for the bit reversal in hamming_dec
    # hamming_dec extracts: nibble = (bits[3]<<3)|(bits[2]<<2)|(bits[1]<<1)|bits[0]
    # which reverses the data bits. So LUT[k] decodes to reversed k.
    # To encode nibble n: find k such that reversed(k) = n, then codeword = LUT[k]
    # reversed(k) = ((k&1)<<3)|((k&2)<<1)|((k&4)>>1)|((k&8)>>3)
    def reverse4(x):
        return ((x&1)<<3)|((x&2)<<1)|((x&4)>>1)|((x&8)>>3)
    for k in range(16):
        if reverse4(k) == nibble:
            return cw_LUT[k]
    return 0  # shouldn't reach


def interleave_v1(codewords, sf_app, cw_len):
    """INVERSE of gr-lora_sdr deinterleave_v1:
    deinter[j][(i-j-1+cw_len)%cw_len] = inter[i][j]
    => inter[i][j] = deinter[j][(i-j-1+cw_len)%cw_len]
    Where deinter[j] = codeword j (sf_app codewords of cw_len bits)
    and inter[i] = symbol i (cw_len symbols of sf_app bits)"""
    deinter = np.zeros((sf_app, cw_len), dtype=int)
    for j in range(sf_app):
        for k in range(cw_len):
            deinter[j][k] = (codewords[j] >> (cw_len - 1 - k)) & 1

    inter = np.zeros((cw_len, sf_app), dtype=int)
    for i in range(cw_len):
        for j in range(sf_app):
            inter[i][j] = deinter[j][(i - j - 1 + cw_len) % cw_len]

    symbols = []
    for i in range(cw_len):
        val = 0
        for j in range(sf_app):
            val = (val << 1) | inter[i][j]
        symbols.append(val)
    return symbols


def interleave_v2(codewords, sf_app, cw_len):
    """INVERSE of rpp0 deinterleave:
    deinter[i][j] = inter[(i+j)%cw_len][sf_app-1-i]
    => inter[k][sf_app-1-i] = deinter[i][(k-i+cw_len)%cw_len] ... complex inverse
    Let's just build it by iterating."""
    deinter = np.zeros((sf_app, cw_len), dtype=int)
    for i in range(sf_app):
        for j in range(cw_len):
            deinter[i][j] = (codewords[i] >> (cw_len - 1 - j)) & 1

    inter = np.zeros((cw_len, sf_app), dtype=int)
    for i in range(sf_app):
        for j in range(cw_len):
            k = (i + j) % cw_len
            inter[k][sf_app - 1 - i] = deinter[i][j]

    symbols = []
    for i in range(cw_len):
        val = 0
        for j in range(sf_app):
            val = (val << 1) | inter[i][j]
        symbols.append(val)
    return symbols


def interleave_v3(codewords, sf_app, cw_len):
    """INVERSE of v3 deinterleave: deinter[j][(i+j)%cw_len] = inter[i][j]
    => inter[i][j] = deinter[j][(i+j)%cw_len]"""
    deinter = np.zeros((sf_app, cw_len), dtype=int)
    for j in range(sf_app):
        for k in range(cw_len):
            deinter[j][k] = (codewords[j] >> (cw_len - 1 - k)) & 1

    inter = np.zeros((cw_len, sf_app), dtype=int)
    for i in range(cw_len):
        for j in range(sf_app):
            inter[i][j] = deinter[j][(i + j) % cw_len]

    symbols = []
    for i in range(cw_len):
        val = 0
        for j in range(sf_app):
            val = (val << 1) | inter[i][j]
        symbols.append(val)
    return symbols


def gray_encode(x):
    return x ^ (x >> 1)

def gray_decode(x):
    n = x
    m = x >> 1
    while m:
        n ^= m
        m >>= 1
    return n


def encode_header(payload_len, has_crc=True, cr=1):
    """Full LoRa TX encoding of header → 8 chirp symbol values.
    Returns dict of {config_name: [8 symbol values]} for all convention combos."""
    nibbles = compute_header_nibbles(payload_len, has_crc, cr)
    codewords = [hamming_encode_84(n) for n in nibbles]

    results = {}
    for iname, ifn in [("iv1", interleave_v1), ("iv2", interleave_v2), ("iv3", interleave_v3)]:
        syms = ifn(codewords, SF, 8)
        for gname, gfn in [("gray_enc", gray_encode), ("gray_dec", gray_decode), ("no_gray", lambda x: x)]:
            chirp_vals = [gfn(s) for s in syms]
            results[f"{iname}_{gname}"] = chirp_vals
    return results, nibbles, codewords


# ════════════════════════════════════════════════════════════════
#  IQ Signal Processing
# ════════════════════════════════════════════════════════════════

def build_upchirp_gr(N, os_factor, sym_id=0):
    """gr-lora_sdr chirp formula from utilities.h"""
    N_os = N * os_factor
    chirp = np.zeros(N_os, dtype=np.complex64)
    n_fold = N_os - sym_id * os_factor
    for i in range(N_os):
        nn = float(i)
        if i < n_fold:
            chirp[i] = np.exp(1j * 2 * np.pi * (nn*nn/(2*N*os_factor**2) + (sym_id/N - 0.5)*nn/os_factor))
        else:
            chirp[i] = np.exp(1j * 2 * np.pi * (nn*nn/(2*N*os_factor**2) + (sym_id/N - 1.5)*nn/os_factor))
    return chirp.astype(np.complex64)


def dechirp_bin(samples, ref_chirp, N, os):
    N_os = N * os
    if len(samples) < N_os:
        return -1, 0.0
    mixed = samples[:N_os] * ref_chirp[:N_os]
    fft_out = np.fft.fft(mixed)
    folded = np.zeros(N, dtype=np.complex128)
    for i in range(os):
        folded += fft_out[i*N:(i+1)*N]
    mag = np.abs(folded)
    peak = np.argmax(mag)
    noise = np.sum(mag) - mag[peak]
    snr = mag[peak] / (noise/(N-1)) if noise > 0 else 999
    return int(peak), float(snr)


def find_preambles(r, downchirp, min_run=8, min_snr=5):
    """Find all preamble locations in resampled IQ data."""
    n_sym = len(r) // N_OS - 1
    bins = np.zeros(n_sym, dtype=int)
    snrs = np.zeros(n_sym, dtype=float)
    for i in range(n_sym):
        b, s = dechirp_bin(r[i*N_OS:(i+1)*N_OS], downchirp, N, OS)
        bins[i] = b
        snrs[i] = s

    preambles = []
    i = 0
    while i < n_sym:
        if snrs[i] < min_snr:
            i += 1
            continue
        run_bin = bins[i]
        run_start = i
        while i < n_sym and bins[i] == run_bin and snrs[i] > min_snr * 0.6:
            i += 1
        run_len = i - run_start
        if run_len >= min_run:
            # Verify sync words
            sw1 = run_start + run_len
            sw2 = sw1 + 1
            if sw2 < n_sym:
                cfo = int(run_bin)
                sw1_ok = abs(bins[sw1] - (NET_ID1 + cfo) % N) <= 2
                sw2_ok = abs(bins[sw2] - (NET_ID2 + cfo) % N) <= 2
                if sw1_ok and sw2_ok:
                    avg_snr = float(np.mean(snrs[run_start:run_start+run_len]))
                    preambles.append({
                        'sym': run_start, 'len': run_len, 'cfo': cfo,
                        'snr': avg_snr, 'bins': bins, 'snrs': snrs
                    })
    return preambles


def extract_header_bins(r, downchirp, preamble, sfd_len=2.0):
    """Extract 8 header symbol FFT bins after a detected preamble."""
    data_offset = preamble['len'] + 2 + sfd_len  # preamble + 2 sync + SFD
    ds = int(preamble['sym'] * N_OS + data_offset * N_OS)
    bins = []
    min_snr = 999
    for i in range(8):
        if ds + (i+1)*N_OS > len(r):
            return None, 0
        b, s = dechirp_bin(r[ds+i*N_OS:ds+(i+1)*N_OS], downchirp, N, OS)
        bins.append(b)
        min_snr = min(min_snr, s)
    return bins, min_snr


# ════════════════════════════════════════════════════════════════
#  MODE: CAPTURE
# ════════════════════════════════════════════════════════════════

def do_capture(args):
    """Run simultaneous RTL-SDR + Heltec sniffer capture."""
    try:
        import serial
    except ImportError:
        print("ERROR: pip install pyserial")
        sys.exit(1)

    ch = args.ch - 1  # 0-indexed
    ch_freq = UL_CHANNELS[ch]
    duration = args.duration
    iq_file = args.output or f"/tmp/superlink_cal_{ch+1}.iq"
    log_file = iq_file.replace('.iq', '.log')

    print(f"=== SuperLink Calibration Capture ===")
    print(f"  Channel:  UL CH{ch+1} ({ch_freq/1e6:.1f} MHz)")
    print(f"  Duration: {duration}s")
    print(f"  IQ file:  {iq_file}")
    print(f"  Log file: {log_file}")
    print(f"  Sniffer:  {args.port}")
    print()

    # Open serial
    ser = serial.Serial(args.port, 115200, timeout=0.1)
    time.sleep(0.5)
    ser.read(4096)  # drain

    # Park sniffer on target channel
    park_cmd = str(ch + 1)
    ser.write(park_cmd.encode())
    time.sleep(0.5)
    resp = ser.read(4096).decode('utf-8', errors='replace')
    print(f"[SNIFFER] {resp.strip()}")

    # Start RTL-SDR capture
    rtl_cmd = [
        'rtl_sdr', '-f', str(CENTER_FREQ), '-s', str(SAMPLE_RATE),
        '-n', str(SAMPLE_RATE * duration), '-g', '40', iq_file
    ]
    print(f"[RTL-SDR] Starting: {' '.join(rtl_cmd)}")
    rtl_proc = subprocess.Popen(rtl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    capture_start = time.time()
    print(f"[RTL-SDR] Capture started at {datetime.now().isoformat()}")

    # Collect sniffer packets
    packets = []
    line_buf = ""
    current_pkt = None

    def save_and_exit(signum=None, frame=None):
        rtl_proc.terminate()
        ser.close()
        with open(log_file, 'w') as f:
            json.dump({
                'capture_start': capture_start,
                'channel': ch + 1,
                'channel_freq_hz': ch_freq,
                'center_freq_hz': CENTER_FREQ,
                'sample_rate': SAMPLE_RATE,
                'iq_file': iq_file,
                'packets': packets,
            }, f, indent=2)
        print(f"\n[DONE] {len(packets)} packets logged to {log_file}")
        sys.exit(0)

    signal.signal(signal.SIGINT, save_and_exit)

    print(f"[CAPTURE] Running for {duration}s (Ctrl-C to stop early)...")
    print()

    try:
        while time.time() - capture_start < duration + 2:
            data = ser.read(512)
            if not data:
                # Check if rtl_sdr finished
                if rtl_proc.poll() is not None:
                    break
                continue

            line_buf += data.decode('utf-8', errors='replace')
            while '\n' in line_buf:
                line, line_buf = line_buf.split('\n', 1)
                line = line.strip()
                if not line:
                    continue

                wall_time = time.time()

                # Parse packet header
                pkt_match = re.match(
                    r'\[PKT #(\d+)\s+t=(\d+)\]\s+(.+?)\s+\|\s+len=(\d+)\s+\|\s+RSSI=([-\d.]+)\s+\|\s+SNR=([-\d.]+)\s+\|\s+CRC=(\w+)',
                    line
                )
                if pkt_match:
                    current_pkt = {
                        'wall_time': wall_time,
                        'capture_offset_s': wall_time - capture_start,
                        'pkt_num': int(pkt_match.group(1)),
                        'millis': int(pkt_match.group(2)),
                        'channel': pkt_match.group(3).strip(),
                        'length': int(pkt_match.group(4)),
                        'rssi': float(pkt_match.group(5)),
                        'snr': float(pkt_match.group(6)),
                        'crc': pkt_match.group(7),
                    }
                    print(f"  {line}")
                    continue

                # Parse hex dump
                hex_match = re.match(r'\s*HEX:\s+((?:[0-9A-Fa-f]{2}\s*)+)', line)
                if hex_match and current_pkt:
                    hex_str = hex_match.group(1).strip()
                    current_pkt['hex'] = hex_str
                    packets.append(current_pkt)
                    t_off = current_pkt['capture_offset_s']
                    print(f"  HEX: {hex_str}  [t={t_off:.3f}s → sample ~{int(t_off*SAMPLE_RATE)}]")
                    current_pkt = None

    except Exception as e:
        print(f"Error: {e}")
    finally:
        save_and_exit()


# ════════════════════════════════════════════════════════════════
#  MODE: CALIBRATE
# ════════════════════════════════════════════════════════════════

def do_calibrate(args):
    """Use sniffer ground truth to determine correct LoRa SF5 decode chain."""
    log_file = args.log
    iq_file = args.iq

    with open(log_file) as f:
        log = json.load(f)

    packets = log['packets']
    ch_freq = log['channel_freq_hz']
    freq_offset = ch_freq - log['center_freq_hz']

    print(f"=== Calibration ===")
    print(f"  IQ file: {iq_file}")
    print(f"  Channel: UL CH{log['channel']} ({ch_freq/1e6:.1f} MHz)")
    print(f"  Packets: {len(packets)} from sniffer")
    print()

    if not packets:
        print("No packets to calibrate with!")
        return

    # Load and preprocess IQ
    print("Loading IQ...")
    raw = np.fromfile(iq_file, dtype=np.uint8)
    i_data = (raw[0::2].astype(np.float32) - 127.5) / 127.5
    q_data = (raw[1::2].astype(np.float32) - 127.5) / 127.5
    cx = (i_data + 1j * q_data).astype(np.complex64)
    del raw, i_data, q_data

    print("Frequency shifting...")
    t = np.arange(len(cx), dtype=np.float64) / SAMPLE_RATE
    cx *= np.exp(-1j * 2 * np.pi * freq_offset * t).astype(np.complex64)
    del t

    print("Resampling 2.4→0.5 MSPS...")
    Nx = len(cx)
    X = np.fft.fft(cx)
    N_up = Nx * INTERP
    X_up = np.zeros(N_up, dtype=np.complex128)
    half = Nx // 2
    X_up[:half] = X[:half]
    X_up[N_up - half:] = X[half:]
    X_up *= INTERP
    r = np.fft.ifft(X_up)[::DECIM].astype(np.complex64)
    del cx, X, X_up
    print(f"  {len(r)} samples ({len(r)/DECODER_RATE:.1f}s)")

    # Generate reference chirp
    downchirp = np.conj(build_upchirp_gr(N, OS, 0))

    # Find all preambles
    print("\nFinding preambles...")
    preambles = find_preambles(r, downchirp)
    print(f"  Found {len(preambles)} preamble(s)")

    if not preambles:
        print("No preambles found! Check signal quality.")
        return

    # For each sniffer packet, compute expected header symbols
    print("\n=== Matching sniffer packets to IQ preambles ===")

    for pkt in packets:
        pkt_len = pkt['length']
        crc_ok = pkt['crc'] == 'OK'
        t_offset = pkt['capture_offset_s']

        print(f"\n--- Sniffer packet: len={pkt_len}, CRC={'OK' if crc_ok else 'FAIL'}, "
              f"t={t_offset:.3f}s ---")

        # Compute ground truth: expected symbol values for all convention combos
        all_expected, nibbles, codewords = encode_header(pkt_len, has_crc=True, cr=1)
        print(f"  Expected header nibbles: {nibbles}")
        print(f"  Expected codewords: {[hex(c) for c in codewords]}")

        # Expected IQ sample offset
        expected_sample = int(t_offset * DECODER_RATE)

        # Try each preamble
        for pream in preambles:
            pream_sample = pream['sym'] * N_OS
            pream_time = pream_sample / DECODER_RATE

            # Only consider preambles within ±2s of expected time
            if abs(pream_time - t_offset) > 2.0:
                continue

            print(f"\n  Preamble at t={pream_time:.3f}s (sym {pream['sym']}), "
                  f"CFO={pream['cfo']}, SNR={pream['snr']:.1f}")

            # Try both SFD lengths
            for sfd_len in [2.0, 2.25]:
                header_bins, min_snr = extract_header_bins(r, downchirp, pream, sfd_len)
                if header_bins is None:
                    continue

                cfo = pream['cfo']
                print(f"    SFD={sfd_len}: raw_bins={header_bins} min_SNR={min_snr:.1f}")

                # Try each offset to correct raw bins
                for offset in [-1, 0, 1]:
                    corrected = [(b + offset - cfo) % N for b in header_bins]

                    # Compare against all expected symbol sets
                    for config_name, expected_syms in all_expected.items():
                        if corrected == expected_syms:
                            print(f"\n    *** MATCH! offset={offset} config={config_name} ***")
                            print(f"    Raw bins:    {header_bins}")
                            print(f"    Corrected:   {corrected}")
                            print(f"    Expected:    {expected_syms}")
                            print(f"    Convention:  offset={offset}, {config_name}")
                            return  # Found it!

                    # Also try with fine timing adjustments
                    for dt in [-N_OS//4, N_OS//4]:
                        ds_adj = int(pream['sym'] * N_OS + (pream['len'] + 2 + sfd_len) * N_OS) + dt
                        adj_bins = []
                        for i in range(8):
                            if ds_adj + (i+1)*N_OS > len(r):
                                break
                            b, _ = dechirp_bin(r[ds_adj+i*N_OS:ds_adj+(i+1)*N_OS], downchirp, N, OS)
                            adj_bins.append(b)
                        if len(adj_bins) < 8:
                            continue
                        for off2 in [-1, 0, 1]:
                            corr2 = [(b + off2 - cfo) % N for b in adj_bins]
                            for config_name, expected_syms in all_expected.items():
                                if corr2 == expected_syms:
                                    print(f"\n    *** MATCH! dt={dt} offset={off2} config={config_name} ***")
                                    print(f"    Raw bins:    {adj_bins}")
                                    print(f"    Corrected:   {corr2}")
                                    print(f"    Expected:    {expected_syms}")
                                    return

    print("\n\n*** NO EXACT MATCH FOUND ***")
    print("Dumping closest matches for manual analysis...")

    # Show what we have for manual comparison
    for pream in preambles:
        for sfd_len in [2.0]:
            header_bins, min_snr = extract_header_bins(r, downchirp, pream, sfd_len)
            if header_bins is None or min_snr < 3:
                continue
            cfo = pream['cfo']
            corrected = [(b - cfo) % N for b in header_bins]
            print(f"\n  Preamble sym={pream['sym']} CFO={cfo} SNR={pream['snr']:.1f}")
            print(f"  Header bins (raw):       {header_bins}")
            print(f"  Header bins (corrected): {corrected}")
            print(f"  Header bins (corr, -1):  {[(b-1-cfo)%N for b in header_bins]}")

            # Show expected for each sniffer packet
            for pkt in packets[:3]:
                all_exp, nib, _ = encode_header(pkt['length'], has_crc=True, cr=1)
                print(f"  Expected for len={pkt['length']} (nibbles {nib}):")
                for name, syms in sorted(all_exp.items()):
                    print(f"    {name:20s}: {syms}")


# ════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="SuperLink LoRa SF5 calibration")
    sub = parser.add_subparsers(dest='mode')

    cap = sub.add_parser('capture', help='Run simultaneous capture')
    cap.add_argument('--port', default='/dev/cu.usbserial-0001', help='Sniffer serial port')
    cap.add_argument('--ch', type=int, default=6, help='UL channel (1-8)')
    cap.add_argument('--duration', type=int, default=30, help='Capture duration (seconds)')
    cap.add_argument('--output', help='Output IQ file path')

    cal = sub.add_parser('calibrate', help='Calibrate decode chain')
    cal.add_argument('--iq', required=True, help='IQ capture file')
    cal.add_argument('--log', required=True, help='Sniffer log file (JSON)')

    args = parser.parse_args()
    if args.mode == 'capture':
        do_capture(args)
    elif args.mode == 'calibrate':
        do_calibrate(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
