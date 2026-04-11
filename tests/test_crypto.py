"""Tests for SuperLink crypto primitives."""
import pysodium
import pytest
from superlink.crypto import generate_keypair, compute_shared_secret, derive_session_key


def test_generate_keypair_sizes():
    """Keypair must be 32 bytes each."""
    privkey, pubkey = generate_keypair()
    assert len(privkey) == 32
    assert len(pubkey) == 32


def test_generate_keypair_unique():
    """Each call produces a different keypair."""
    k1 = generate_keypair()
    k2 = generate_keypair()
    assert k1[0] != k2[0]
    assert k1[1] != k2[1]


def test_keypair_consistency():
    """Public key must be derivable from private key."""
    privkey, pubkey = generate_keypair()
    derived_pub = pysodium.crypto_scalarmult_curve25519_base(privkey)
    assert derived_pub == pubkey


def test_shared_secret_agreement():
    """Both sides must derive the same shared secret."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()

    secret_a = compute_shared_secret(priv_a, pub_b)
    secret_b = compute_shared_secret(priv_b, pub_a)

    assert len(secret_a) == 32
    assert secret_a == secret_b


def test_shared_secret_differs_per_pair():
    """Different keypairs produce different shared secrets."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    priv_c, pub_c = generate_keypair()

    s_ab = compute_shared_secret(priv_a, pub_b)
    s_ac = compute_shared_secret(priv_a, pub_c)
    assert s_ab != s_ac


def test_derive_session_key_deterministic():
    """Same inputs must produce same session key."""
    shared = bytes(range(32))
    pub_a = bytes(range(32, 64))
    pub_b = bytes(range(64, 96))

    key1 = derive_session_key(shared, pub_a, pub_b)
    key2 = derive_session_key(shared, pub_a, pub_b)

    assert len(key1) == 32
    assert key1 == key2


def test_derive_session_key_pubkey_order_matters():
    """Swapping pubkey order must produce different key."""
    shared = bytes(range(32))
    pub_a = bytes(range(32, 64))
    pub_b = bytes(range(64, 96))

    key1 = derive_session_key(shared, pub_a, pub_b)
    key2 = derive_session_key(shared, pub_b, pub_a)

    assert key1 != key2


def test_derive_session_key_with_context():
    """Context bytes change the derived key."""
    shared = bytes(range(32))
    pub_a = bytes(range(32, 64))
    pub_b = bytes(range(64, 96))

    key1 = derive_session_key(shared, pub_a, pub_b)
    key2 = derive_session_key(shared, pub_a, pub_b, context=b"extra")

    assert key1 != key2
