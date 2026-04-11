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
      - Gateway (initiator=False): first=local, second=remote
      - Sensor (initiator=True): first=remote, second=local

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
