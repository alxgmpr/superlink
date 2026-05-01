"""
SuperLink LoRa application-layer ADOPT_REQUEST / ADOPT_RESPONSE codec.

Recovered 2026-04-30 from static RE of UniFi Protect (UNVR fw v5.0.16,
webpack module 41118 = ./src/middleware/devices/loraBridges/helpers/
applicationLayer/messages.ts). Full reference at
docs/protocol/superlink_application_layer.md.

Lifted out of tools/mock_controller/server.py so the Pi gateway
(tools/sx1302/superlink/gateway.py) can reuse it. Same module is
imported by the mock via a sys.path hack.

ADOPT_REQUEST (controller -> sensor, 70 bytes wire):
    [1B messageId=0x02] [1B messageTag]
    [32B gatewayPublicKey] [32B gatewayFallbackPublicKey]
    [4B networkId BE]

ADOPT_RESPONSE (sensor -> controller, 66 bytes wire):
    [1B messageId=0x03] [1B messageTag (echoes request)]
    [32B devicePublicKey] [32B deviceFallbackPublicKey]
"""

from __future__ import annotations

import hashlib

import pysodium


# MessageId enum values we use directly.
MSG_ADOPT_REQUEST = 0x02
MSG_ADOPT_RESPONSE = 0x03

# 32B salt baked into Protect's deviceAdopt KDF (deviceAdopt.ts).
KDF_SALT_H = bytes.fromhex(
    "70be68514ce7b81328d9f3215855c5675336ea88a08a728df7fce95cc8970a59"
)

# Default networkId (4-byte BE trailer in ADOPT_REQUEST). The controller
# picks one per console; the test bridge's console used 0x048F = 1167. Reused
# here so on-wire bytes stay consistent with prior captures, but any 32-bit
# value works as long as the same one is used for the lifetime of a console.
DEFAULT_NETWORK_ID = 0x048F


def kdf_E(my_priv: bytes, their_pub: bytes) -> bytes:
    """Persistent-key KDF from Protect's deviceAdopt.ts.

        E(my_priv, their_pub) = blake2b32(
            X25519(my_priv, their_pub)
            || base * my_priv
            || their_pub
            || H )
    """
    if len(my_priv) != 32 or len(their_pub) != 32:
        raise ValueError("expected 32-byte priv/pub")
    shared = pysodium.crypto_scalarmult_curve25519(my_priv, their_pub)
    my_pub = pysodium.crypto_scalarmult_curve25519_base(my_priv)
    return hashlib.blake2b(
        shared + my_pub + their_pub + KDF_SALT_H, digest_size=32
    ).digest()


def encode_adopt_request(
    message_tag: int,
    gw_pub: bytes,
    gw_fb_pub: bytes,
    network_id: int = DEFAULT_NETWORK_ID,
) -> bytes:
    """Build the 70-byte ADOPT_REQUEST wire body."""
    if len(gw_pub) != 32 or len(gw_fb_pub) != 32:
        raise ValueError("pubkeys must be 32 bytes")
    return (
        bytes([MSG_ADOPT_REQUEST, message_tag & 0xFF])
        + gw_pub
        + gw_fb_pub
        + network_id.to_bytes(4, "big")
    )


def decode_adopt_response(body: bytes) -> tuple[int, bytes, bytes]:
    """Parse a 66-byte ADOPT_RESPONSE.

    Returns (messageTag, devicePublicKey, deviceFallbackPublicKey).
    Raises ValueError on wrong messageId or short body.
    """
    if len(body) < 66:
        raise ValueError(f"ADOPT_RESPONSE too short: {len(body)} bytes (need 66)")
    if body[0] != MSG_ADOPT_RESPONSE:
        raise ValueError(f"not an ADOPT_RESPONSE (messageId=0x{body[0]:02x})")
    return body[1], body[2:34], body[34:66]
