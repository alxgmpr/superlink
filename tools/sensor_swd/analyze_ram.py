#!/usr/bin/env python3
"""Analyze an STM32WLE5 (ST50HE) SRAM dump from the SuperLink motion sensor.

RDP1 blocks flash but not SRAM, so `savebin <f> 0x20000000 0x10000` over SWD yields
64 KB of live RAM. This script hunts for key material.

Usage:
    uv run --with cryptography python analyze_ram.py <dump.bin> [--key HEX] [--base 0x20000000]

  --key HEX   Search the dump for a known key (e.g. from tools/keyhook/capture_key.sh).
              This is the ground-truth cross-check: a hit proves the live session key is
              resident in the read-protected sensor. HEX may be 32 or 64 bytes.

Without --key it runs X25519/Ed25519 keypair self-consistency tests and an entropy map.
Note: the SuperLink *session key* is a symmetric 32-byte blob (XSalsa20-Poly1305/BLAKE2b),
so keypair tests will NOT find it — use --key with a bridge-captured value for that.
"""
import sys, math, argparse
from collections import Counter

def ent(w):
    if not w: return 0.0
    c = Counter(w); n = len(w)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--key", help="known key hex to search for (32 or 64 bytes)")
    ap.add_argument("--base", default="0x20000000")
    a = ap.parse_args()
    BASE = int(a.base, 16)
    d = open(a.dump, "rb").read()
    print(f"{a.dump}: {len(d)} bytes @ {a.base}")

    if a.key:
        kb = bytes.fromhex(a.key.replace(" ", ""))
        print(f"\n=== searching for {len(kb)}-byte key {kb.hex()} ===")
        idx = 0; hits = []
        while (j := d.find(kb, idx)) >= 0:
            hits.append(j); idx = j + 1
        if hits:
            for h in hits:
                print(f"  MATCH @ 0x{BASE + h:08x}")
        else:
            print("  no match — try halves, byte-swapped, or a fresh session-synced dump")
            # also try each 32-byte half
            for name, half in [("first32", kb[:32]), ("last32", kb[-32:])]:
                if len(kb) >= 32 and (j := d.find(half)) >= 0:
                    print(f"  {name} MATCH @ 0x{BASE + j:08x}: {half.hex()}")
        return

    # keypair self-consistency (needs cryptography)
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("install cryptography (uv run --with cryptography ...) for keypair tests")
        return

    def xpub(s):
        try: return X25519PrivateKey.from_private_bytes(s).public_key().public_bytes_raw()
        except Exception: return None
    def edpub(s):
        try: return Ed25519PrivateKey.from_private_bytes(s).public_key().public_bytes_raw()
        except Exception: return None

    xh = eh = esk = 0
    for off in range(0, len(d) - 32):
        s = d[off:off+32]
        if s.count(0) > 24: continue
        xp = xpub(s)
        if xp and xp in d and d.find(xp) != off:
            print(f"  X25519 priv@0x{BASE+off:08x}={s.hex()} pub@0x{BASE+d.find(xp):08x}"); xh += 1
        ep = edpub(s)
        if ep:
            if d[off+32:off+64] == ep:
                print(f"  Ed25519 sk(seed||pub)@0x{BASE+off:08x} seed={s.hex()}"); esk += 1
            elif ep in d and d.find(ep) != off:
                print(f"  Ed25519 seed@0x{BASE+off:08x} pub@0x{BASE+d.find(ep):08x}"); eh += 1
    print(f"\nX25519 hits={xh}  Ed25519 seed->pub={eh}  Ed25519 sk={esk}")
    if xh == eh == esk == 0:
        print("(expected: session key is symmetric — use --key with a bridge-captured value)")

if __name__ == "__main__":
    main()
