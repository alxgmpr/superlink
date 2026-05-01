"""
Phase Y5 step 1: try to recover the inner secretbox key for the captured Y3
70B Class B grant body, treating addDevice.key as a PSK shared between the
real UniFi controller and the sensor.

If the inner ct verifies under any candidate (kdf_inputs, nonce_inputs)
combo, we have the algorithm — at which point we can generate fresh grants
on the mock controller side without needing the sensor's static private key
or the UniFi Network app's source.

If nothing verifies after exhausting plausible combos, hypothesis A
(addDevice.key as PSK) is wrong; we'd need either sensor flash or UniFi
Java RE (hypothesis B path).

Run: python3 tools/grant_crack/crack_y3.py
"""

from __future__ import annotations

import hashlib
import itertools
from typing import Iterable

import nacl.bindings as nb


# ---------------------------------------------------------------------------
# Y3 grant inputs (all known public from the capture + mock state).
# ---------------------------------------------------------------------------
GRANT_HEX = (
    "029c4b144c10e0703533e445b8cbeffc3d98704bbc873ba68b13a86269b7b2cd"
    "4378cf15f1b061326f8e2c5ed91dc3b54e147696679e968d7d136df7561f0298"
    "9b2b0000048f"
)
ADD_DEVICE_KEY = bytes.fromhex(
    "c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db"
)
SENSOR_MAC = bytes.fromhex("9041b22e9a53")
NETWORK_ID_BE = bytes.fromhex("0000048f")  # the trailer
NETWORK_ID_INT = int.from_bytes(NETWORK_ID_BE, "big")  # 1167

grant = bytes.fromhex(GRANT_HEX)
assert len(grant) == 70, len(grant)
NN = grant[1]
EPH_PUB = grant[2:34]            # bytes [0..31] of middle, X25519 u-coord LE
AUTH = grant[34:66]              # bytes [32..63] of middle, 16B Poly1305 + 16B ct (or vice versa)
TRAILER = grant[66:]
assert TRAILER == NETWORK_ID_BE


# ---------------------------------------------------------------------------
# Candidate KDF inputs.
#
# We enumerate (combo of buffers, blake2b key, blake2b person, blake2b salt).
# blake2b-32 is the only hash the bridge uses on the LoRa side (keypair
# derivation), so it's the obvious default. We also try SHA-256 just in
# case.
#
# Buffers we try (treating addDevice.key as a PSK):
#   K  = ADD_DEVICE_KEY
#   E  = EPH_PUB                       (32 B)
#   M  = SENSOR_MAC                    (6 B)
#   N  = NN                            (1 B)
#   I  = NETWORK_ID_BE                 (4 B)
#   I2 = NETWORK_ID_BE little-endian
#   T  = the 4B trailer literally
# Combos enumerated as concatenations in plausible orders.
# ---------------------------------------------------------------------------

K = ADD_DEVICE_KEY
E = EPH_PUB
M = SENSOR_MAC
N = bytes([NN])
I_BE = NETWORK_ID_BE
I_LE = NETWORK_ID_BE[::-1]
T = TRAILER

KDF_INPUTS: list[bytes] = []

# Singles + pairs that include K and/or E
base = [K, E, K + E, E + K, K + M, E + M, K + E + M, E + K + M, K + M + E,
        E + M + K, M + K, M + E, M + K + E, M + E + K]
for b in base:
    KDF_INPUTS.append(b)
    KDF_INPUTS.append(b + N)
    KDF_INPUTS.append(N + b)
    KDF_INPUTS.append(b + I_BE)
    KDF_INPUTS.append(b + I_LE)
    KDF_INPUTS.append(I_BE + b)
    KDF_INPUTS.append(I_LE + b)
    KDF_INPUTS.append(b + T)
    KDF_INPUTS.append(T + b)
    KDF_INPUTS.append(b + N + I_BE)
    KDF_INPUTS.append(b + I_BE + N)
    KDF_INPUTS.append(N + b + I_BE)

# Variants that XOR or shift by NN (rolling counter could feed in)
KDF_INPUTS.append(K)
KDF_INPUTS.append(bytes(a ^ NN for a in K))
KDF_INPUTS.append(bytes(a ^ NN for a in K) + E)
KDF_INPUTS.append(E + bytes(a ^ NN for a in K))

# ASCII tag variants — bridge uses "UBN_" tag NONCEs elsewhere
ASCII_TAGS = [b"UBNG", b"UBNP", b"UBNL", b"UBND", b"UBNV", b"UBNU",
              b"GRANT", b"grant", b"\x00\x00\x00\x00"]
tagged = []
for tag in ASCII_TAGS:
    for b in [K + E, E + K, K, E, K + E + M, E + K + M]:
        tagged.append(b + tag)
        tagged.append(tag + b)
KDF_INPUTS.extend(tagged)

# Deduplicate while preserving order
seen = set()
uniq = []
for b in KDF_INPUTS:
    if b in seen:
        continue
    seen.add(b)
    uniq.append(b)
KDF_INPUTS = uniq


def kdf_candidates(input_bytes: bytes) -> Iterable[tuple[str, bytes]]:
    """Yield (label, 32B key) candidates for one input buffer."""
    yield ("blake2b32", hashlib.blake2b(input_bytes, digest_size=32).digest())
    yield ("blake2b32_K_keyed",
           hashlib.blake2b(input_bytes, digest_size=32, key=K).digest())
    # blake2b with personalization tied to the protocol (the bridge KDF
    # uses 16B "personal" tags on libsodium gh_init — try a few)
    for tag in [b"UBNT-LORA-GRANT0", b"ubnt-lora-grant\0", b"GRANTKEY00000000",
                b"superlink-grant0", b"ubnt-superlink00"]:
        try:
            yield (f"blake2b32_p_{tag.rstrip(b'\\0').decode(errors='replace')}",
                   hashlib.blake2b(input_bytes, digest_size=32,
                                   person=tag).digest())
        except ValueError:
            pass
    yield ("sha256",
           hashlib.sha256(input_bytes).digest())


# ---------------------------------------------------------------------------
# Candidate nonces (24 B for XSalsa20-Poly1305).
# ---------------------------------------------------------------------------

def nonce_candidates() -> Iterable[tuple[str, bytes]]:
    yield ("zeros", b"\x00" * 24)
    yield ("eph_pub_first24", EPH_PUB[:24])
    yield ("eph_pub_last24", EPH_PUB[8:32])
    # NN-padded nonces
    yield ("nn_le_padded", bytes([NN]) + b"\x00" * 23)
    yield ("nn_be_padded", b"\x00" * 23 + bytes([NN]))
    yield ("nn_repeated", bytes([NN]) * 24)
    # ASCII tag tail (UBNU/UBNV pattern)
    for tag in [b"UBNU", b"UBNV", b"UBNG", b"UBNP", b"UBNL", b"UBND",
                b"GRNT", b"grnt"]:
        yield (f"zeros20_{tag.decode()}", b"\x00" * 20 + tag)
    # network-id permutations
    yield ("zeros20_netid_be", b"\x00" * 20 + I_BE)
    yield ("zeros20_netid_le", b"\x00" * 20 + I_LE)
    # NN || mac || ZEROS shape
    yield ("nn_mac_pad", bytes([NN]) + M + b"\x00" * 17)
    yield ("mac_nn_pad", M + bytes([NN]) + b"\x00" * 17)
    # eph_pub-derived (truncated blake2b)
    yield ("blake2b24_E",
           hashlib.blake2b(EPH_PUB, digest_size=24).digest())
    yield ("blake2b24_E_K",
           hashlib.blake2b(EPH_PUB + K, digest_size=24).digest())
    yield ("blake2b24_K_E",
           hashlib.blake2b(K + EPH_PUB, digest_size=24).digest())


def try_open(key: bytes, nonce: bytes, ct: bytes) -> bytes | None:
    if len(key) != 32 or len(nonce) != 24 or len(ct) != 32:
        return None
    try:
        return nb.crypto_secretbox_open(ct, nonce, key)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# DH-based derivations: maybe addDevice.key is the sensor's *private* key
# (controller stores it for adoption convenience). Then both controller and
# sensor can derive shared = scalarmult(addDevice.key, eph_pub). We can do
# the same. Also try treating it as a pubkey (no scalarmult possible from
# our side without eph_priv, but worth noting it's not viable).
# ---------------------------------------------------------------------------

def dh_shared_candidates() -> list[tuple[str, bytes]]:
    out = []
    try:
        s = nb.crypto_scalarmult(ADD_DEVICE_KEY, EPH_PUB)
        out.append(("scalarmult(K, eph_pub)", s))
    except Exception as e:
        print(f"scalarmult(K, eph_pub) failed: {e}")
    # Also try with K reversed (LE/BE flip)
    try:
        s = nb.crypto_scalarmult(ADD_DEVICE_KEY[::-1], EPH_PUB)
        out.append(("scalarmult(K_rev, eph_pub)", s))
    except Exception as e:
        pass
    # And with eph_pub reversed
    try:
        s = nb.crypto_scalarmult(ADD_DEVICE_KEY, EPH_PUB[::-1])
        out.append(("scalarmult(K, eph_pub_rev)", s))
    except Exception as e:
        pass
    return out


def main() -> int:
    print(f"Y3 grant: NN={NN:02x} eph_pub={EPH_PUB.hex()}")
    print(f"          auth={AUTH.hex()}  trailer={TRAILER.hex()}")
    print(f"addDevice.key (PSK): {ADD_DEVICE_KEY.hex()}")
    print(f"Sensor MAC: {SENSOR_MAC.hex()}")
    print()

    nonces = list(nonce_candidates())
    dh_shareds = dh_shared_candidates()
    print(f"DH shareds derivable from K + eph_pub: {len(dh_shareds)}")
    for label, sec in dh_shareds:
        print(f"  {label} = {sec.hex()}")
    print()

    # Add DH shareds as additional KDF inputs (alone and combined with eph_pub,
    # MAC, network id — same shape combos we used for addDevice.key direct).
    for label, sec in dh_shareds:
        for combo in [sec, sec + E, E + sec, sec + E + M, sec + M, sec + I_BE,
                      sec + bytes([NN]), bytes([NN]) + sec, sec + T, T + sec,
                      sec + E + bytes([NN]), sec + bytes([NN]) + I_BE]:
            if combo not in seen:
                seen.add(combo)
                KDF_INPUTS.append(combo)
        # Also try the shared as a blake2b key
        for inp in [E, M, E + M, M + E, K, E + K, K + E,
                    bytes([NN]) + E, E + bytes([NN])]:
            label2 = f"blake2b32_keyed_shared_{label}"
            try:
                kk = hashlib.blake2b(inp, digest_size=32, key=sec).digest()
                # Inject as a synthetic 'kdf_inputs' entry by stuffing a
                # marker — but we need it to fall into kdf_candidates loop.
                # Simplest: also append (inp || sec) to KDF_INPUTS so plain
                # blake2b32 will produce a similar mix.
                if (inp + sec) not in seen:
                    seen.add(inp + sec)
                    KDF_INPUTS.append(inp + sec)
                if (sec + inp) not in seen:
                    seen.add(sec + inp)
                    KDF_INPUTS.append(sec + inp)
            except Exception:
                pass

    print(f"Total KDF input combos after DH expansion: {len(KDF_INPUTS)}")
    print(f"Trying {len(KDF_INPUTS)} KDF input combos × ~6 hash variants × "
          f"{len(nonces)} nonce shapes "
          f"= ~{len(KDF_INPUTS) * 6 * len(nonces):,} attempts")
    print()

    # Two interpretations of `auth` ordering:
    # - tag||ct  (libsodium crypto_secretbox layout: 16B Poly1305 || 16B ct)
    # - ct||tag  (uncommon, but worth trying)
    layouts = [("tag||ct", AUTH), ("ct||tag", AUTH[16:] + AUTH[:16])]

    attempts = 0
    hits = []
    for combo_idx, kdf_input in enumerate(KDF_INPUTS):
        for kdf_label, key in kdf_candidates(kdf_input):
            for nonce_label, nonce in nonces:
                for layout_label, ct in layouts:
                    attempts += 1
                    pt = try_open(key, nonce, ct)
                    if pt is not None:
                        hits.append((combo_idx, kdf_input, kdf_label,
                                     nonce_label, layout_label, key, nonce, pt))
                        print(f"!! HIT after {attempts:,} attempts:")
                        print(f"   kdf_input(idx={combo_idx})={kdf_input.hex()}")
                        print(f"   kdf={kdf_label} key={key.hex()}")
                        print(f"   nonce={nonce_label} = {nonce.hex()}")
                        print(f"   layout={layout_label}")
                        print(f"   PT(16B) = {pt.hex()}")
                        print()

    print(f"Total attempts: {attempts:,}")
    print(f"Hits: {len(hits)}")
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
