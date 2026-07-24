#!/usr/bin/env python3
"""Scan SRAM dumps captured during a firmware update for DECRYPTED-firmware
fragments in transit — the payoff of the OTA-capture route (grabs plaintext the
bootloader produces to program flash, without ever needing the fused decrypt key).

Signatures of plaintext ARM firmware in a 64 KB SRAM buffer that isn't there at
rest: an ARM Cortex-M vector table (initial SP in SRAM, reset handler in flash
with thumb bit), sharp low-entropy code windows amid otherwise-high-entropy OTA
staging, and ASCII string runs. Diffs across dumps also surface regions that
CHANGE during the transfer (the staging buffer).

Usage: fw_fragment_scan.py dump1.bin dump2.bin ...
"""
import sys, struct, math
from collections import Counter

BASE = 0x20000000
WIN = 256

def ent(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def vectors(d):
    """Scan for word-aligned ARM vector-table starts (SP in SRAM, reset in flash)."""
    hits = []
    for off in range(0, len(d) - 8, 4):
        sp, rst = struct.unpack_from("<II", d, off)
        if 0x20000000 <= sp <= 0x20010000 and 0x08000000 <= rst <= 0x08060000 and (rst & 1):
            hits.append((off, sp, rst))
    return hits

def lowent_windows(d, thresh=6.0):
    """Contiguous WIN-byte windows whose entropy is low (code/data, not encrypted)."""
    out = []
    for off in range(0, len(d) - WIN, WIN):
        e = ent(d[off:off+WIN])
        if e < thresh and d[off:off+WIN].count(0) < WIN - 8:
            out.append((off, e))
    return out

def ascii_runs(d, minlen=6):
    runs = []
    cur = b""
    start = 0
    for i, ch in enumerate(d):
        if 32 <= ch < 127:
            if not cur: start = i
            cur += bytes([ch])
        else:
            if len(cur) >= minlen: runs.append((start, cur.decode("ascii", "replace")))
            cur = b""
    return runs

def main():
    files = sys.argv[1:]
    if not files:
        print("usage: fw_fragment_scan.py dump*.bin"); return
    print(f"scanning {len(files)} dumps for firmware fragments\n")
    interesting = []
    # baseline: a rest dump (no update) has known keystore + FreeRTOS strings but
    # no vector table / no big low-entropy code blocks. Flag anything beyond that.
    for f in files:
        d = open(f, "rb").read()
        if len(d) != 0x10000:
            continue
        vt = vectors(d)
        low = lowent_windows(d)
        # a rest dump has a handful of low-ent windows (stacks, buffers). A dump
        # with decrypted code has many contiguous low-ent windows.
        if vt or len(low) > 40:
            interesting.append((f, vt, low))
            print(f"[{f.split('/')[-1]}] vector-tables={len(vt)} low-ent-windows={len(low)}")
            for off, sp, rst in vt[:5]:
                print(f"    VECTOR TABLE @0x{BASE+off:08x}: SP=0x{sp:08x} reset=0x{rst:08x}")
    if not interesting:
        print("no firmware-fragment signatures found across the dumps.")
        print("(if the update was rejected/never transferred, nothing to catch;")
        print(" if it transferred, try dumping faster / more often during decrypt.)")
        return
    # cross-dump changing regions (the staging buffer)
    print("\n=== new ASCII strings not in the first dump (transient firmware strings) ===")
    base = set(s for _, s in ascii_runs(open(files[0], "rb").read()))
    seen = set()
    for f, *_ in interesting:
        for _, s in ascii_runs(open(f, "rb").read()):
            if s not in base and s not in seen and len(s) >= 8:
                seen.add(s); print(f"    {s!r}")
                if len(seen) > 60: break

if __name__ == "__main__":
    main()
