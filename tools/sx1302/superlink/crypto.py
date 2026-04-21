"""
SuperLink crypto primitives.

Curve25519 DH, BLAKE2b KDF, and challenge authentication
for the SuperLink connection handshake.
"""

import pysodium


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ephemeral Curve25519 keypair.

    Returns:
        (private_key, public_key) — both 32 bytes.
    """
    privkey = pysodium.randombytes(32)
    # Clamp private key per Curve25519 spec
    privkey = bytearray(privkey)
    privkey[0] &= 248
    privkey[31] &= 127
    privkey[31] |= 64
    privkey = bytes(privkey)
    pubkey = pysodium.crypto_scalarmult_curve25519_base(privkey)
    return privkey, pubkey


def compute_shared_secret(local_privkey: bytes, remote_pubkey: bytes) -> bytes:
    """Compute Curve25519 ECDH shared secret.

    Args:
        local_privkey: Our 32-byte private key.
        remote_pubkey: Their 32-byte public key.

    Returns:
        32-byte shared secret.
    """
    return pysodium.crypto_scalarmult_curve25519(local_privkey, remote_pubkey)


def derive_session_key(shared_secret: bytes, pubkey_first: bytes,
                       pubkey_second: bytes, context: bytes = b"") -> bytes:
    """Derive a 32-byte session key via BLAKE2b KDF.

    Matches decompiled sub_3af5a in lorabrd. The firmware uses a common
    keypair object (keypair + 0x54) for both sides. Inside sub_3af5a:

        r6 = &remote_pubkey_vec   (keypair + 8)
        r8 = &local_pubkey_vec    (keypair + 0x14)
        if (keypair+4 == 0)       // NOT initiator (gateway)
            swap(r6, r8)
        blake2b(shared || *r6 || *r8 || *(keypair+0x30) || arg3_vec)

    After the swap, BOTH sides hash in the order:
        shared_secret || gateway_pubkey || sensor_pubkey || context

    The `context` vector at keypair+0x30 is populated by the keypair
    constructor sub_3b054 from arg4 of sub_54020 (the gateway-session
    constructor). Tracing back: sub_54020 is invoked by sub_48f28 ←
    sub_50344 ← sub_5be1c (JSON "add device" handler) with arg4 = the
    "key" JSON field. For factory pairing, the controller provisions
    "key" and "fallbackKey" as the same hardcoded Ubi default key
    (47be3dff…), so keypair+0x30 == pairing_key in that case.

    arg3_vec (the 5th hash component) is an empty std::vector<uint8_t>
    in the initial-pairing flow (sub_52090 zeros var_c0 before the call),
    so it contributes zero bytes to the hash.

    Args:
        shared_secret: 32-byte Curve25519 shared secret.
        pubkey_first: gateway pubkey (always first after swap).
        pubkey_second: sensor pubkey.
        context: keypair+0x30 vector — pass the pairing_key for the
            factory-pairing flow.

    Returns:
        32-byte session key.
    """
    state = pysodium.crypto_generichash_init(32, b"")
    pysodium.crypto_generichash_update(state, shared_secret)
    pysodium.crypto_generichash_update(state, pubkey_first)
    pysodium.crypto_generichash_update(state, pubkey_second)
    if context:
        pysodium.crypto_generichash_update(state, context)
    return pysodium.crypto_generichash_final(state, 32)


def build_challenge_nonce(is_response: bool = False) -> bytes:
    """Build a 24-byte nonce for challenge authentication.

    From Ghidra analysis of FUN_0003bf58:
      - 16 zero bytes
      - 4 bytes ASCII marker at offset 16
      - 4 zero bytes padding

    The marker is "UBNU" for challenge request, "UBNV" for response.
    """
    nonce = bytearray(24)
    marker = b"UBNV" if is_response else b"UBNU"
    nonce[16:20] = marker
    return bytes(nonce)


def secretbox_encrypt(plaintext: bytes, nonce: bytes, key: bytes) -> bytes:
    """Encrypt with XSalsa20-Poly1305 (crypto_secretbox_easy).

    Args:
        plaintext: Message to encrypt.
        nonce: 24-byte nonce.
        key: 32-byte key.

    Returns:
        Ciphertext with 16-byte Poly1305 MAC prepended.
    """
    return pysodium.crypto_secretbox(plaintext, nonce, key)


def secretbox_decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """Decrypt XSalsa20-Poly1305 (crypto_secretbox_open_easy).

    Args:
        ciphertext: Ciphertext with 16-byte Poly1305 MAC prepended.
        nonce: 24-byte nonce.
        key: 32-byte key.

    Returns:
        Decrypted plaintext.

    Raises:
        Exception if MAC verification fails (wrong key or tampered data).
    """
    return pysodium.crypto_secretbox_open(ciphertext, nonce, key)
