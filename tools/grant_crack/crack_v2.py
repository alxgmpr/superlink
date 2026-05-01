"""
Y5 grant crack v2 — focused hypothesis space.

Hypothesis: addDevice.key is the sensor's static X25519 private key (the
factory-burned secret that the controller has stored from adoption time).
That makes the 70B grant a Noise_N-shaped one-shot:

   sensor static (priv = addDevice.key, pub = base × addDevice.key)
   controller picks ephemeral keypair (eph_priv, eph_pub)
   shared = X25519(eph_priv, sensor_static_pub)
          = X25519(addDevice.key, eph_pub)        ← we can compute this side
   key    = KDF(shared || pubkeys || addDevice.key)
   ct     = AEAD(key, nonce, 16B payload, ad?)
   wire   = 02 || NN || eph_pub || ct || 0000048f

We try several plausible KDFs (blake2b32 of canonical orderings, including
the 4-input shape from the session-key KDF), several AEAD primitives
(libsodium secretbox = XSalsa20+Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305),
and several nonce/AD shapes.
"""

from __future__ import annotations

import hashlib
import itertools
from typing import Iterable

import nacl.bindings as nb


# ---------------------------------------------------------------------------
# Inputs.
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

grant = bytes.fromhex(GRANT_HEX)
NN = grant[1]
EPH_PUB = grant[2:34]
AUTH = grant[34:66]
TRAILER = grant[66:]

K = ADD_DEVICE_KEY
M = SENSOR_MAC
N = bytes([NN])
T = TRAILER
# Bridge-side per-clientID persistent value (controller also has it, used in
# WS authorize KDF). Worth a try as a 4th KDF input.
BRIDGE_SALT = bytes.fromhex(
    "69b1d4a63a301106494473b25c23c372a1ba54fbbdbd4fd47ed638460e425f07"
)
B = BRIDGE_SALT

# X25519 derivations available to us, treating K as a private key.
SENSOR_STATIC_PUB_GUESS = nb.crypto_scalarmult_base(K)         # base × K
SHARED = nb.crypto_scalarmult(K, EPH_PUB)                      # K × E

print(f"NN          = 0x{NN:02x}")
print(f"eph_pub     = {EPH_PUB.hex()}")
print(f"AUTH (32B)  = {AUTH.hex()}")
print(f"trailer     = {TRAILER.hex()}")
print(f"K (addDev)  = {K.hex()}")
print(f"K × base    = {SENSOR_STATIC_PUB_GUESS.hex()}   ← guessed sensor static pub")
print(f"K × E       = {SHARED.hex()}                    ← shared if K=sensor_priv")
print()


def b2b(buf: bytes, n: int = 32, key: bytes = b"", person: bytes = b"",
        salt: bytes = b"") -> bytes:
    return hashlib.blake2b(buf, digest_size=n, key=key,
                           person=person if person else b"",
                           salt=salt if salt else b"").digest()


def b2s(buf: bytes, n: int = 32, key: bytes = b"") -> bytes:
    return hashlib.blake2s(buf, digest_size=n, key=key).digest()


def sha256(buf: bytes) -> bytes:
    return hashlib.sha256(buf).digest()


def hkdf_sha256(ikm: bytes, salt: bytes = b"", info: bytes = b"",
                length: int = 32) -> bytes:
    import hmac

    if len(salt) == 0:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


# ---------------------------------------------------------------------------
# Candidate (key, nonce, ct_layout) generator.
#
# AUTH is 32B. For libsodium crypto_secretbox: layout is [16B Poly1305 || 16B ct].
# For ChaCha20-Poly1305 / IETF: layout is [16B ct || 16B tag] (encrypt_then_mac
# via separate API). For Noise_N with ChaChaPoly: cipher returns ct||tag.
# ---------------------------------------------------------------------------

def kdf_keys() -> Iterable[tuple[str, bytes]]:
    """Yield (label, 32B key) candidates."""
    SP = SENSOR_STATIC_PUB_GUESS
    S = SHARED

    # 1. Direct K (addDevice.key as raw secretbox key)
    yield ("raw_K", K)

    # 2. Single-input blake2b32 of plausible buffers
    for label, buf in [
        # BRIDGE_SALT inclusion (per-clientID shared between ctl and bridge)
        ("b2b_B", B),
        ("b2b_E_B", EPH_PUB + B),
        ("b2b_B_E", B + EPH_PUB),
        ("b2b_K_B", K + B),
        ("b2b_B_K", B + K),
        ("b2b_E_K_B", EPH_PUB + K + B),
        ("b2b_E_B_K", EPH_PUB + B + K),
        ("b2b_B_E_K", B + EPH_PUB + K),
        ("b2b_B_K_E", B + K + EPH_PUB),
        ("b2b_S_E_B_K", S + EPH_PUB + B + K),
        ("b2b_S_E_K_B", S + EPH_PUB + K + B),
        # original entries follow
        ("b2b_K", K),
        ("b2b_S", S),
        ("b2b_E", EPH_PUB),
        ("b2b_S_K", S + K),
        ("b2b_K_S", K + S),
        ("b2b_E_K", EPH_PUB + K),
        ("b2b_K_E", K + EPH_PUB),
        ("b2b_S_E", S + EPH_PUB),
        ("b2b_E_S", EPH_PUB + S),
        ("b2b_S_E_K", S + EPH_PUB + K),
        ("b2b_E_S_K", EPH_PUB + S + K),
        ("b2b_K_E_S", K + EPH_PUB + S),
        # 4-input shape mirroring session_key KDF
        # update[0]=shared update[1]=pub_a update[2]=pub_b update[3]=K
        ("b2b_S_E_SP_K", S + EPH_PUB + SP + K),
        ("b2b_S_SP_E_K", S + SP + EPH_PUB + K),
        ("b2b_E_SP_S_K", EPH_PUB + SP + S + K),
        ("b2b_SP_E_S_K", SP + EPH_PUB + S + K),
        ("b2b_S_E_K_SP", S + EPH_PUB + K + SP),
        # With sensor MAC added
        ("b2b_S_E_K_M", S + EPH_PUB + K + M),
        ("b2b_S_M_E_K", S + M + EPH_PUB + K),
        # With NN counter
        ("b2b_S_E_K_N", S + EPH_PUB + K + N),
        ("b2b_S_N_E_K", S + N + EPH_PUB + K),
    ]:
        yield (label, b2b(buf, 32))
        # blake2b keyed mode with K as key
        yield (f"{label}_keyedK", b2b(buf, 32, key=K))
        # blake2s
        yield (f"{label}_b2s", b2s(buf, 32))
        # SHA-256
        yield (f"{label}_sha", sha256(buf))

    # 3. Noise_N MixHash + MixKey style derivations (canonical Noise patterns)
    for proto in [
        b"Noise_N_25519_ChaChaPoly_SHA256",
        b"Noise_N_25519_ChaChaPoly_BLAKE2s",
        b"Noise_N_25519_ChaChaPoly_BLAKE2b",
        b"Noise_N_25519_AESGCM_SHA256",
        b"Noise_N_25519_AESGCM_BLAKE2s",
        b"Noise_N_25519_AESGCM_BLAKE2b",
        b"Noise_X_25519_ChaChaPoly_SHA256",
        b"Noise_K_25519_ChaChaPoly_SHA256",
    ]:
        # Noise: h = HASH(proto) padded to HASHLEN
        for hashfn, hlen in [(sha256, 32), (b2s, 32), (b2b, 32)]:
            if len(proto) <= hlen:
                h = proto + b"\x00" * (hlen - len(proto))
            else:
                h = hashfn(proto) if hashfn is not b2b else b2b(proto, hlen)
            ck = h
            # MixHash(e_pub): h = HASH(h || e_pub)
            h = hashfn(h + EPH_PUB) if hashfn is not b2b else b2b(h + EPH_PUB, hlen)
            # MixKey(shared): ck, k = HKDF(ck, shared, 2)
            # For SHA-256 use HKDF-SHA-256, for BLAKE2 use blake2-as-HMAC analog
            if hashfn is sha256:
                k_material = hkdf_sha256(SHARED, salt=ck, length=64)
                new_ck, new_k = k_material[:32], k_material[32:]
                yield (f"noise_{proto.decode()}_sha", new_k)
            else:
                # BLAKE2 doesn't have a standard HKDF; libsodium hashes
                # (ck || shared) for kdf
                kk = hashfn(ck + SHARED) if hashfn is not b2b else b2b(ck + SHARED, 32)
                yield (f"noise_{proto.decode()}_b2", kk)


def nonces() -> Iterable[tuple[str, bytes, int]]:
    """Yield (label, nonce_bytes, nonce_len)."""
    # Length 24 (XSalsa20)
    yield ("zeros24", b"\x00" * 24, 24)
    yield ("nn_le24", bytes([NN]) + b"\x00" * 23, 24)
    yield ("nn_be24", b"\x00" * 23 + bytes([NN]), 24)
    yield ("eph24a", EPH_PUB[:24], 24)
    yield ("eph24b", EPH_PUB[8:32], 24)
    yield ("nn_pad24", bytes([NN]) * 24, 24)
    for tag in [b"UBNG", b"UBNP", b"UBNL", b"UBND", b"UBNV", b"UBNU",
                b"GRNT", b"grnt"]:
        yield (f"zeros20_{tag.decode()}_24", b"\x00" * 20 + tag, 24)
    yield ("zeros20_netid_24", b"\x00" * 20 + T, 24)
    yield ("nn_mac_pad24", bytes([NN]) + M + b"\x00" * 17, 24)
    yield ("eph_first8_zeros16_24", EPH_PUB[:8] + b"\x00" * 16, 24)
    # Length 12 (ChaCha20-Poly1305 IETF / AES-GCM)
    yield ("zeros12", b"\x00" * 12, 12)
    yield ("nn_le12", bytes([NN]) + b"\x00" * 11, 12)
    yield ("nn_be12", b"\x00" * 11 + bytes([NN]), 12)
    yield ("eph12a", EPH_PUB[:12], 12)
    yield ("eph12b", EPH_PUB[20:32], 12)
    yield ("zeros8_netid12", b"\x00" * 8 + T, 12)
    yield ("zeros8_nn_pad12", b"\x00" * 8 + bytes([NN]) + b"\x00" * 3, 12)
    yield ("noise_ietf12", b"\x00" * 12, 12)  # Noise_N first message: nonce=0
    # Length 8 (some libsodium primitives)
    yield ("zeros8", b"\x00" * 8, 8)
    yield ("nn_le8", bytes([NN]) + b"\x00" * 7, 8)


# ---------------------------------------------------------------------------
# AEAD trial functions (each tries to verify+decrypt).
# ---------------------------------------------------------------------------

def try_secretbox(key: bytes, nonce: bytes, ct32: bytes) -> bytes | None:
    """libsodium crypto_secretbox: PT||PT (16B Poly1305 prefix in wire)."""
    if len(nonce) != 24 or len(key) != 32:
        return None
    try:
        return nb.crypto_secretbox_open(ct32, nonce, key)
    except Exception:
        return None


def try_chachapoly_ietf(key: bytes, nonce: bytes, ct32: bytes,
                        ad: bytes = b"") -> bytes | None:
    """ChaCha20-Poly1305 IETF (12B nonce). ct32 = 16B ct || 16B tag."""
    if len(key) != 32 or len(nonce) != 12 or len(ct32) != 32:
        return None
    try:
        return nb.crypto_aead_chacha20poly1305_ietf_decrypt(ct32, ad, nonce, key)
    except Exception:
        return None


def try_xchacha20poly1305(key: bytes, nonce: bytes, ct32: bytes,
                          ad: bytes = b"") -> bytes | None:
    """XChaCha20-Poly1305 (24B nonce). ct32 = 16B ct || 16B tag."""
    if len(key) != 32 or len(nonce) != 24 or len(ct32) != 32:
        return None
    try:
        return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(ct32, ad, nonce, key)
    except Exception:
        return None


def try_chachapoly_legacy(key: bytes, nonce: bytes, ct32: bytes,
                          ad: bytes = b"") -> bytes | None:
    """ChaCha20-Poly1305 (8B nonce). ct32 = 16B ct || 16B tag."""
    if len(key) != 32 or len(nonce) != 8 or len(ct32) != 32:
        return None
    try:
        return nb.crypto_aead_chacha20poly1305_decrypt(ct32, ad, nonce, key)
    except Exception:
        return None


def main() -> int:
    keys = list(kdf_keys())
    print(f"Trying {len(keys)} keys × ~{sum(1 for _ in nonces())} nonces "
          f"× 4 AEAD variants × multiple AD/layout shapes")

    # AD candidates for AEAD variants that take associated data
    ads = [b"", grant[:2], grant[:2] + TRAILER, EPH_PUB, EPH_PUB + TRAILER, M]

    # ct layout candidates: tag||ct, ct||tag
    layouts = [("tag||ct", AUTH[:16] + AUTH[16:]),
               ("ct||tag", AUTH[16:] + AUTH[:16])]

    attempts = 0
    hits = []

    for klabel, key in keys:
        for nlabel, nonce, nlen in nonces():
            for layout_label, ct in layouts:
                # secretbox (24B nonce, layout tag||ct only — its API expects
                # combined ct including the prepended Poly1305 tag)
                if nlen == 24:
                    pt = try_secretbox(key, nonce, ct)
                    attempts += 1
                    if pt is not None:
                        hits.append(("secretbox", klabel, nlabel, layout_label,
                                     b"", pt))
                        print(f"!! HIT secretbox {klabel} / {nlabel} / "
                              f"{layout_label}: PT={pt.hex()}")

                if nlen == 24:
                    for ad in ads:
                        pt = try_xchacha20poly1305(key, nonce, ct, ad)
                        attempts += 1
                        if pt is not None:
                            hits.append(("xchachapoly", klabel, nlabel,
                                         layout_label, ad, pt))
                            print(f"!! HIT xchachapoly {klabel} / {nlabel} / "
                                  f"{layout_label} / ad={ad.hex() or 'empty'}: "
                                  f"PT={pt.hex()}")

                if nlen == 12:
                    for ad in ads:
                        pt = try_chachapoly_ietf(key, nonce, ct, ad)
                        attempts += 1
                        if pt is not None:
                            hits.append(("chachapoly_ietf", klabel, nlabel,
                                         layout_label, ad, pt))
                            print(f"!! HIT chachapoly_ietf {klabel} / {nlabel} / "
                                  f"{layout_label} / ad={ad.hex() or 'empty'}: "
                                  f"PT={pt.hex()}")

                if nlen == 8:
                    for ad in ads:
                        pt = try_chachapoly_legacy(key, nonce, ct, ad)
                        attempts += 1
                        if pt is not None:
                            hits.append(("chachapoly_legacy", klabel, nlabel,
                                         layout_label, ad, pt))
                            print(f"!! HIT chachapoly_legacy {klabel} / "
                                  f"{nlabel} / {layout_label} / ad="
                                  f"{ad.hex() or 'empty'}: PT={pt.hex()}")

    print()
    print(f"attempts: {attempts:,}")
    print(f"hits: {len(hits)}")
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
