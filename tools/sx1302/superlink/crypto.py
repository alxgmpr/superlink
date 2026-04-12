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

    Matches the decompiled FUN_0003af5a from lorabrd:
      BLAKE2b(shared_secret || pubkey_first || pubkey_second || context)

    The pubkey order depends on who initiated the connection:
      - Gateway (initiator=False): first=remote(sensor), second=local(gateway)
      - Sensor (initiator=True): first=local(sensor), second=remote(gateway)
    In both cases, the sensor's pubkey comes first and the gateway's second.

    Args:
        shared_secret: 32-byte Curve25519 shared secret.
        pubkey_first: First public key (see ordering above).
        pubkey_second: Second public key.
        context: Additional context bytes (TBD — needs keyhook capture to confirm).

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
