# Standalone SuperLink Gateway — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python gateway that can beacon, pair with factory-default SuperLink sensors via Curve25519 DH, and decrypt their data frames.

**Architecture:** Extends the existing `tools/sx1302/superlink/` package. New `gateway.py` module handles the connection state machine. `decoder.py` gains frame encoding functions. `hal.py` gains TX support. All crypto via `pysodium`.

**Tech Stack:** Python 3.11+, pysodium (libsodium), ctypes (SX1302 HAL), pytest

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `tests/conftest.py` | Create | Pytest config, shared fixtures |
| `tests/fixtures/captured_frames.py` | Create | Known-good frames, keys, nonces from captures |
| `tests/test_decoder.py` | Create | Frame parse/build round-trip, encrypt/decrypt, MIC |
| `tests/test_crypto.py` | Create | DH, KDF, challenge, nonce construction |
| `tests/test_gateway.py` | Create | State machine transitions, frame handling |
| `tools/sx1302/superlink/decoder.py` | Modify | Add encrypt_payload, compute_mic, build_frame |
| `tools/sx1302/superlink/hal.py` | Modify | Add lgw_pkt_tx_s, send(), DL channel constants, tx_enable |
| `tools/sx1302/superlink/gateway.py` | Create | State machine, crypto, CLI entry point |
| `tools/sx1302/superlink/__init__.py` | Modify | No change needed (package marker) |

---

### Task 1: Test Infrastructure and Captured Fixtures

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/fixtures/__init__.py`
- Create: `tests/fixtures/captured_frames.py`

- [ ] **Step 1: Create conftest.py with sys.path setup**

```python
# tests/conftest.py
import sys
from pathlib import Path

# Add the superlink package to path so tests can import it
sys.path.insert(0, str(Path(__file__).parent.parent / "tools" / "sx1302"))
```

- [ ] **Step 2: Create fixtures package**

```python
# tests/fixtures/__init__.py
```

- [ ] **Step 3: Create captured_frames.py with real captured data**

All data below is from actual OTA captures and keyhook logs (docs/protocol/ota_captures.md, crypto_keys_captured.md).

```python
# tests/fixtures/captured_frames.py
"""
Known-good captured frames, keys, and nonces from OTA captures.
These serve as protocol ground truth for all tests.

Sources:
  - docs/protocol/ota_captures.md (2026-04-04, 2026-04-10)
  - docs/protocol/crypto_keys_captured.md (keyhook captures)
"""

# --- Sensor identity ---
SENSOR_MAC = bytes.fromhex("9041B22E9A53")

# --- Default pairing key (from lorabrd .rodata) ---
DEFAULT_PAIRING_KEY = bytes.fromhex(
    "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
)

# --- Captured OTA frame: 19B standard UL data (door state) ---
# From ota_captures.md first capture session
FRAME_19B_RAW = bytes.fromhex("E054 9041B22E9A53 5B11 9CFFC24C 8A41BC35D6".replace(" ", ""))
# After decryption with session key, counter = 0x5B - 5 = 0x56 = 86:
# MIC = first 4 bytes of decrypted, payload = remaining 5 bytes
# Decrypted payload: 0C 00 0F 00 01 (DOOR CLOSED)

# --- Captured OTA frame: 36B extended UL data ---
# From ota_captures.md second capture session (confirmed decrypted)
FRAME_36B_RAW = bytes.fromhex("E054 9041B22E9A53 0D2D".replace(" ", ""))
# The encrypted portion (26 bytes) follows but we use the full raw from capture
# Key: 3bfc41760a9eb10c01989bfdbfc384f770617d7a5bfa56acc72d90edeefb8c06
# Nonce counter = 0x0D - 5 = 8
# Decrypted: [MIC 4B] 0C 00 01 00 00 08 6E 04 02 00 64 E0 07 03 00 60 0C 16 00 0F 00 00

FRAME_36B_DECRYPTED_PAYLOAD = bytes.fromhex(
    "0C00010000086E04020064E0070300600C1600 0F0000".replace(" ", "")
)

# --- Nonce construction examples ---
# UL data frame: [Mctrl][Dctrl][MAC][SeqHi][SeqLo][13 zeros][Counter]
NONCE_UL_DATA = bytes.fromhex(
    "E054 9041B22E9A53 0D2D 00000000000000000000000000 08".replace(" ", "")
)
# Mctrl=0xE0, Dctrl=0x54, MAC=9041B22E9A53, SeqHi=0x0D, SeqLo=0x2D, Counter=8

# --- DL data frame (16B) ---
FRAME_16B_DL_RAW = bytes.fromhex("E063 9041B22E9A53 4081 DB3C4692D1AD".replace(" ", ""))
# Dctrl=0x63, DL data, 6B encrypted (4B MIC + 2B payload)
# DL counter = 4

# --- Reconnection handshake frames (OTA, 2026-04-10) ---
HANDSHAKE_CONN_63B = {
    "size": 63, "dctrl": 0x42, "seq_hi": 0xDE, "seq_lo": 0x34,
    "description": "Connection/challenge, encrypted with OLD session key, counter=0",
}
HANDSHAKE_RSP_16B = {
    "size": 16, "dctrl": 0x53, "seq_hi": 0x01, "seq_lo": 0x2C,
    "description": "Connection response, 2B payload",
}
HANDSHAKE_SETUP_FRAMES = [
    {"size": 92, "dctrl": 0x44, "seq_hi": 0x02, "seq_lo": 0x81, "payload_len": 78},
    {"size": 41, "dctrl": 0x44, "seq_hi": 0x03, "seq_lo": 0x82, "payload_len": 27},
    {"size": 20, "dctrl": 0x44, "seq_hi": 0x04, "seq_lo": 0x83, "payload_len": 6},
    {"size": 41, "dctrl": 0x44, "seq_hi": 0x05, "seq_lo": 0x84, "payload_len": 27},
]

# --- Challenge nonces (from keyhook) ---
# Challenge request nonce ends with ASCII "UBNU" (55424e55)
CHALLENGE_REQ_NONCE_SUFFIX = bytes.fromhex("55424e55")  # "UBNU"
# Challenge response nonce ends with ASCII "UBNV" (55424e56)
CHALLENGE_RSP_NONCE_SUFFIX = bytes.fromhex("55424e56")  # "UBNV"

# --- Counter rules ---
UL_COUNTER_OFFSET = 5   # UL data counter = seq_hi - 5 (for reconnection)
DL_COUNTER = 4           # DL data counter = 4 (fixed after reconnection handshake)

# --- Channel plan ---
UL_CHANNELS_HZ = [
    915_600_000, 915_800_000, 916_000_000, 916_200_000,
    916_400_000, 916_600_000, 916_800_000, 917_000_000,
]
DL_CHANNELS_HZ = [
    920_400_000, 921_000_000, 921_600_000, 922_200_000,
    922_800_000, 923_400_000, 924_000_000, 924_600_000,
]
BEACON_FREQ_HZ = 927_600_000

# UL channel index (0-7) → paired DL channel freq
UL_TO_DL_FREQ = {i: DL_CHANNELS_HZ[i] for i in range(8)}
```

- [ ] **Step 4: Verify fixtures load**

Run: `cd /Volumes/Secondary/superlink && python -c "from tests.fixtures.captured_frames import *; print('OK:', SENSOR_MAC.hex())"`

Expected: `OK: 9041b22e9a53`

- [ ] **Step 5: Commit**

```bash
git add tests/conftest.py tests/fixtures/__init__.py tests/fixtures/captured_frames.py
git commit -m "test: add pytest infrastructure and captured frame fixtures"
```

---

### Task 2: Frame Encoding in decoder.py (TDD)

**Files:**
- Create: `tests/test_decoder.py`
- Modify: `tools/sx1302/superlink/decoder.py`

- [ ] **Step 1: Write failing test for encrypt_payload**

```python
# tests/test_decoder.py
"""Tests for SuperLink frame encoding and decoding."""
import pytest
from superlink.decoder import (
    build_nonce, decrypt_frame, encrypt_payload, parse_frame,
)
from tests.fixtures.captured_frames import SENSOR_MAC


def test_encrypt_decrypt_roundtrip():
    """XSalsa20 encrypt then decrypt should recover the original."""
    key = bytes(range(32))  # deterministic test key
    nonce = build_nonce(0xE0, 0x54, SENSOR_MAC, 0x07, 0x2D, counter=2)
    plaintext = b"\x0C\x00\x0F\x00\x01"  # door closed
    mic = b"\xAA\xBB\xCC\xDD"

    encrypted = encrypt_payload(mic + plaintext, key, nonce)
    assert len(encrypted) == len(mic) + len(plaintext)
    assert encrypted != mic + plaintext  # must be different

    # Decrypt with same key/nonce recovers original
    import pysodium
    decrypted = pysodium.crypto_stream_xor(encrypted, len(encrypted), nonce, key)
    assert decrypted[:4] == mic
    assert decrypted[4:] == plaintext
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_decoder.py::test_encrypt_decrypt_roundtrip -v`

Expected: FAIL — `ImportError: cannot import name 'encrypt_payload'`

- [ ] **Step 3: Implement encrypt_payload in decoder.py**

Add after the `decrypt_frame` function in `tools/sx1302/superlink/decoder.py`:

```python
def encrypt_payload(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypt MIC + payload bytes with XSalsa20.

    Args:
        plaintext: Combined MIC (4 bytes) + payload to encrypt.
        key: 32-byte encryption key.
        nonce: 24-byte XSalsa20 nonce (from build_nonce).

    Returns:
        Encrypted bytes (same length as plaintext).
    """
    if not HAS_CRYPTO:
        raise RuntimeError("pysodium required for encryption")
    return pysodium.crypto_stream_xor(plaintext, len(plaintext), nonce, key)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_decoder.py::test_encrypt_decrypt_roundtrip -v`

Expected: PASS

- [ ] **Step 5: Write failing test for build_frame**

Add to `tests/test_decoder.py`:

```python
def test_build_frame_roundtrip():
    """build_frame output should be parseable by parse_frame."""
    from superlink.decoder import build_frame

    key = bytes(range(32))
    mac = SENSOR_MAC
    payload = b"\x0C\x00\x0F\x00\x01"
    mic = b"\x11\x22\x33\x44"

    raw = build_frame(
        mctrl=0xE0, dctrl=0x54, mac=mac,
        seq_hi=0x07, seq_lo=0x2D,
        mic=mic, payload=payload,
        key=key, counter=2,
    )

    # Should be 10 (header) + 4 (mic) + 5 (payload) = 19 bytes
    assert len(raw) == 19

    # parse_frame should extract header fields
    frame = parse_frame(raw)
    assert frame is not None
    assert frame.mctrl == 0xE0
    assert frame.dctrl == 0x54
    assert frame.mac == mac
    assert frame.seq_hi == 0x07
    assert frame.seq_lo == 0x2D
    assert len(frame.encrypted) == 9  # 4 MIC + 5 payload, encrypted

    # decrypt should recover payload
    frame = decrypt_frame(frame, key, ul_counter_offset=5)
    assert frame.mic == mic
    assert frame.payload == payload
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_decoder.py::test_build_frame_roundtrip -v`

Expected: FAIL — `ImportError: cannot import name 'build_frame'`

- [ ] **Step 7: Implement build_frame in decoder.py**

Add after `encrypt_payload` in `tools/sx1302/superlink/decoder.py`:

```python
def build_frame(mctrl: int, dctrl: int, mac: bytes,
                seq_hi: int, seq_lo: int,
                mic: bytes, payload: bytes,
                key: bytes, counter: int) -> bytes:
    """Build a complete SuperLink frame (header + encrypted MIC + payload).

    Args:
        mctrl: Management control byte (0xE0 for SecureHeader).
        dctrl: Data control byte (e.g. 0x54 for UL data).
        mac: 6-byte MAC address.
        seq_hi: Frame counter high byte.
        seq_lo: Frame counter low byte.
        mic: 4-byte integrity check (plaintext, will be encrypted).
        payload: Plaintext payload bytes.
        key: 32-byte encryption key.
        counter: Nonce counter byte (byte 23 of the nonce).

    Returns:
        Complete frame bytes: [header 10B][encrypted(MIC + payload)].
    """
    header = bytes([mctrl, dctrl]) + mac + bytes([seq_hi, seq_lo])
    nonce = build_nonce(mctrl, dctrl, mac, seq_hi, seq_lo, counter)
    encrypted = encrypt_payload(mic + payload, key, nonce)
    return header + encrypted
```

- [ ] **Step 8: Run test to verify it passes**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_decoder.py -v`

Expected: Both tests PASS

- [ ] **Step 9: Write test for nonce construction against captured data**

Add to `tests/test_decoder.py`:

```python
def test_nonce_matches_capture():
    """Nonce construction must match keyhook-captured nonces."""
    from tests.fixtures.captured_frames import NONCE_UL_DATA

    nonce = build_nonce(0xE0, 0x54, SENSOR_MAC, 0x0D, 0x2D, counter=8)
    assert nonce == NONCE_UL_DATA
    assert len(nonce) == 24
    assert nonce[23] == 8  # counter byte


def test_nonce_counter_zero_padding():
    """Bytes 10-22 must be zero."""
    nonce = build_nonce(0xE0, 0x54, SENSOR_MAC, 0x07, 0x2D, counter=2)
    assert nonce[10:23] == b"\x00" * 13
```

- [ ] **Step 10: Run nonce tests**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_decoder.py -v`

Expected: All tests PASS

- [ ] **Step 11: Commit**

```bash
git add tests/test_decoder.py tools/sx1302/superlink/decoder.py
git commit -m "feat: add frame encoding (encrypt_payload, build_frame) with TDD"
```

---

### Task 3: HAL TX Support

**Files:**
- Modify: `tools/sx1302/superlink/hal.py`
- Create: `tests/test_hal.py`

- [ ] **Step 1: Write test for DL channel constants**

```python
# tests/test_hal.py
"""Tests for SX1302 HAL constants and configuration."""
from superlink.hal import DL_FREQ_HZ, BEACON_FREQ_HZ, UL_TO_DL_FREQ


def test_dl_channel_count():
    """Must have 8 DL channels."""
    assert len(DL_FREQ_HZ) == 8


def test_dl_frequencies():
    """DL frequencies must match protocol spec."""
    expected = [
        920_400_000, 921_000_000, 921_600_000, 922_200_000,
        922_800_000, 923_400_000, 924_000_000, 924_600_000,
    ]
    assert DL_FREQ_HZ == expected


def test_beacon_frequency():
    assert BEACON_FREQ_HZ == 927_600_000


def test_ul_to_dl_mapping():
    """UL channel index 0-7 maps to paired DL frequency."""
    assert UL_TO_DL_FREQ[0] == 920_400_000  # CH1 → CH9
    assert UL_TO_DL_FREQ[7] == 924_600_000  # CH8 → CH16
    assert len(UL_TO_DL_FREQ) == 8
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_hal.py -v`

Expected: FAIL — `ImportError: cannot import name 'DL_FREQ_HZ'`

- [ ] **Step 3: Add DL channel constants to hal.py**

Add after the `IF_TO_UL_CH` dict in `tools/sx1302/superlink/hal.py`:

```python
# --- Downlink channel plan (500 kHz, SF5) ---

DL_FREQ_HZ = [
    920_400_000,  # CH9  (paired with UL CH1)
    921_000_000,  # CH10 (paired with UL CH2)
    921_600_000,  # CH11 (paired with UL CH3)
    922_200_000,  # CH12 (paired with UL CH4)
    922_800_000,  # CH13 (paired with UL CH5)
    923_400_000,  # CH14 (paired with UL CH6)
    924_000_000,  # CH15 (paired with UL CH7)
    924_600_000,  # CH16 (paired with UL CH8)
]

BEACON_FREQ_HZ = 927_600_000  # CH17

# UL channel index (0-7) → paired DL frequency
UL_TO_DL_FREQ = {i: DL_FREQ_HZ[i] for i in range(8)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_hal.py -v`

Expected: PASS

- [ ] **Step 5: Add lgw_pkt_tx_s struct and send method to hal.py**

Add the TX struct definition after `lgw_pkt_rx_s` in `tools/sx1302/superlink/hal.py`:

```python
# TX mode enum
TX_IMMEDIATE = 0
TX_TIMESTAMPED = 1
TX_ON_GPS = 2


class lgw_pkt_tx_s(ctypes.Structure):
    """TX packet structure. Field order matches loragw_hal.h."""
    _fields_ = [
        ("freq_hz", ctypes.c_uint32),
        ("tx_mode", ctypes.c_uint8),
        ("count_us", ctypes.c_uint32),
        ("rf_chain", ctypes.c_uint8),
        ("rf_power", ctypes.c_int8),
        ("modulation", ctypes.c_uint8),
        ("bandwidth", ctypes.c_uint8),
        ("datarate", ctypes.c_uint32),
        ("coderate", ctypes.c_uint8),
        ("invert_pol", ctypes.c_bool),
        ("f_dev", ctypes.c_uint8),
        ("preamble", ctypes.c_uint16),
        ("no_crc", ctypes.c_bool),
        ("no_header", ctypes.c_bool),
        ("size", ctypes.c_uint16),
        ("payload", ctypes.c_uint8 * 256),
    ]
```

**IMPORTANT:** The exact field order and types MUST be verified against `~/sx1302_hal/libloragw/inc/loragw_hal.h` on the RPi before first TX test. The struct above is based on the standard Semtech HAL but may have padding differences. Run `python -c "from superlink.hal import lgw_pkt_tx_s; print(ctypes.sizeof(lgw_pkt_tx_s))"` on the RPi and compare to `sizeof(struct lgw_pkt_tx_s)` in C.

Add to `_setup_prototypes` method:

```python
self._lib.lgw_send.argtypes = [ctypes.POINTER(lgw_pkt_tx_s)]
self._lib.lgw_send.restype = ctypes.c_int
```

Add `send` method to the `SX1302` class:

```python
def send(self, freq_hz: int, payload: bytes,
         rf_power: int = 10, bandwidth: int = BW_500KHZ) -> None:
    """Transmit a frame.

    Args:
        freq_hz: TX frequency in Hz.
        payload: Frame bytes to transmit.
        rf_power: TX power in dBm (default 10).
        bandwidth: LoRa bandwidth (BW_500KHZ for DL, BW_125KHZ for UL).
    """
    pkt = lgw_pkt_tx_s()
    pkt.freq_hz = freq_hz
    pkt.tx_mode = TX_IMMEDIATE
    pkt.rf_chain = 0
    pkt.rf_power = rf_power
    pkt.modulation = MOD_LORA
    pkt.bandwidth = bandwidth
    pkt.datarate = DR_LORA_SF5
    pkt.coderate = CR_LORA_4_5
    pkt.invert_pol = False
    pkt.preamble = 12
    pkt.no_crc = False
    pkt.no_header = False
    pkt.size = len(payload)
    ctypes.memmove(pkt.payload, payload, len(payload))

    rc = self._lib.lgw_send(ctypes.byref(pkt))
    if rc != 0:
        raise RuntimeError(f"lgw_send failed (rc={rc})")
```

Also update `_configure` to enable TX on radio 0. Change the `rf0` config:

```python
rf0.tx_enable = True
```

- [ ] **Step 6: Commit**

```bash
git add tools/sx1302/superlink/hal.py tests/test_hal.py
git commit -m "feat: add SX1302 TX support (DL channels, lgw_send wrapper)"
```

---

### Task 4: Crypto Primitives (TDD)

**Files:**
- Create: `tests/test_crypto.py`
- Create: `tools/sx1302/superlink/crypto.py`

- [ ] **Step 1: Write failing test for Curve25519 keypair generation**

```python
# tests/test_crypto.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_crypto.py::test_generate_keypair_sizes -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'superlink.crypto'`

- [ ] **Step 3: Implement generate_keypair**

```python
# tools/sx1302/superlink/crypto.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_crypto.py::test_generate_keypair_sizes tests/test_crypto.py::test_generate_keypair_unique tests/test_crypto.py::test_keypair_consistency -v`

Expected: PASS

- [ ] **Step 5: Write failing test for DH shared secret**

Add to `tests/test_crypto.py`:

```python
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
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_crypto.py::test_shared_secret_agreement -v`

Expected: FAIL — `ImportError: cannot import name 'compute_shared_secret'`

- [ ] **Step 7: Implement compute_shared_secret**

Add to `tools/sx1302/superlink/crypto.py`:

```python
def compute_shared_secret(local_privkey: bytes, remote_pubkey: bytes) -> bytes:
    """Compute Curve25519 ECDH shared secret.

    Args:
        local_privkey: Our 32-byte private key.
        remote_pubkey: Their 32-byte public key.

    Returns:
        32-byte shared secret.
    """
    return pysodium.crypto_scalarmult_curve25519(local_privkey, remote_pubkey)
```

- [ ] **Step 8: Run test to verify it passes**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_crypto.py -k "shared_secret" -v`

Expected: PASS

- [ ] **Step 9: Write failing test for session key derivation (KDF)**

Add to `tests/test_crypto.py`:

```python
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
```

- [ ] **Step 10: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_crypto.py::test_derive_session_key_deterministic -v`

Expected: FAIL — function exists but signature doesn't match / not yet implemented

- [ ] **Step 11: Implement derive_session_key**

Add to `tools/sx1302/superlink/crypto.py`:

```python
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
```

- [ ] **Step 12: Run all crypto tests**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_crypto.py -v`

Expected: All PASS

- [ ] **Step 13: Commit**

```bash
git add tools/sx1302/superlink/crypto.py tests/test_crypto.py
git commit -m "feat: add crypto primitives (Curve25519 DH, BLAKE2b KDF)"
```

---

### Task 5: Gateway State Machine — Core (TDD)

**Files:**
- Create: `tools/sx1302/superlink/gateway.py`
- Create: `tests/test_gateway.py`

- [ ] **Step 1: Write failing test for state machine initialization**

```python
# tests/test_gateway.py
"""Tests for the gateway connection state machine."""
import pytest
from superlink.gateway import GatewaySession, State
from tests.fixtures.captured_frames import (
    DEFAULT_PAIRING_KEY, SENSOR_MAC, DL_CHANNELS_HZ, BEACON_FREQ_HZ,
)


def test_initial_state():
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    assert session.state == State.IDLE
    assert session.gw_mac == gw_mac
    assert session.session_key is None
    assert session.sensor_mac is None


def test_start_transitions_to_beaconing():
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()
    assert session.state == State.BEACONING
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py::test_initial_state -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'superlink.gateway'`

- [ ] **Step 3: Implement GatewaySession skeleton**

```python
# tools/sx1302/superlink/gateway.py
"""
SuperLink standalone gateway.

Implements the connection state machine for pairing with
factory-default sensors via Curve25519 DH exchange.
"""

import enum
import logging
import time

from .crypto import generate_keypair, compute_shared_secret, derive_session_key
from .decoder import (
    build_frame, build_nonce, decrypt_frame, encrypt_payload,
    format_mac, parse_frame, SuperLinkFrame, DCTRL_TABLE,
)

log = logging.getLogger(__name__)


class State(enum.Enum):
    IDLE = "idle"
    BEACONING = "beaconing"
    WAIT_CONNREQ = "wait_connreq"
    DH_EXCHANGE = "dh_exchange"
    CHALLENGE = "challenge"
    SETUP = "setup"
    ACTIVE = "active"


class GatewaySession:
    """Manages a single sensor connection lifecycle."""

    def __init__(self, gw_mac: bytes, pairing_key: bytes,
                 beacon_interval: float = 240.0):
        self.gw_mac = gw_mac
        self.pairing_key = pairing_key
        self.beacon_interval = beacon_interval

        self.state = State.IDLE
        self.sensor_mac: bytes | None = None
        self.session_key: bytes | None = None

        # DH state
        self._privkey: bytes | None = None
        self._pubkey: bytes | None = None
        self._remote_pubkey: bytes | None = None

        # Sequence counters
        self._tx_seq_hi = 0
        self._tx_seq_lo = 0
        self._ul_counter_offset = 0

        # Timing
        self._last_beacon_time = 0.0

    def start(self):
        """Transition from IDLE to BEACONING."""
        self._privkey, self._pubkey = generate_keypair()
        self.state = State.BEACONING
        self._last_beacon_time = 0.0  # force immediate first beacon
        log.info("Gateway started, entering BEACONING state")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py -v`

Expected: PASS

- [ ] **Step 5: Write failing test for beacon building**

Add to `tests/test_gateway.py`:

```python
def test_beacon_due():
    """Beacon should be due immediately after start."""
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()
    assert session.beacon_due()


def test_build_beacon():
    """Beacon must be a valid plaintext frame with gateway MAC."""
    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()
    beacon = session.build_beacon()

    assert isinstance(beacon, bytes)
    assert len(beacon) >= 10  # at least a header
    # Mctrl should NOT be 0xE0 (beacon is plaintext, not SecureHeader)
    # Exact Mctrl TBD — using 0x00 as placeholder for plaintext
    assert beacon[2:8] == gw_mac  # MAC field is gateway MAC
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py::test_beacon_due -v`

Expected: FAIL — `AttributeError: 'GatewaySession' object has no attribute 'beacon_due'`

- [ ] **Step 7: Implement beacon_due and build_beacon**

Add to `GatewaySession` class in `gateway.py`:

```python
def beacon_due(self) -> bool:
    """Check if it's time to send a beacon."""
    if self.state != State.BEACONING:
        return False
    return (time.monotonic() - self._last_beacon_time) >= self.beacon_interval

def build_beacon(self) -> bytes:
    """Build a plaintext beacon frame.

    NOTE: The exact beacon payload format is unknown. This builds a
    minimal beacon with just the header. The payload must be determined
    by capturing a real beacon from the Ubiquiti gateway.
    """
    # PlainHeader beacon — Mctrl=0x00 (plaintext), Dctrl TBD
    # Using minimal header-only frame for now
    mctrl = 0x00
    dctrl = 0x00  # TBD — beacon dctrl value unknown
    seq_hi = self._tx_seq_hi & 0xFF
    seq_lo = self._tx_seq_lo & 0xFF
    header = bytes([mctrl, dctrl]) + self.gw_mac + bytes([seq_hi, seq_lo])
    self._last_beacon_time = time.monotonic()
    log.info("Built beacon frame (%d bytes)", len(header))
    return header
```

- [ ] **Step 8: Run test to verify it passes**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py -v`

Expected: All PASS

- [ ] **Step 9: Write failing test for handling received UL frames in ACTIVE state**

Add to `tests/test_gateway.py`:

```python
def test_handle_ul_data_in_active_state():
    """In ACTIVE state, received UL data frames should be decrypted."""
    from superlink.decoder import build_frame

    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.start()

    # Manually advance to ACTIVE state with a known session key
    session.state = State.ACTIVE
    session.session_key = bytes(range(32))
    session.sensor_mac = SENSOR_MAC
    session._ul_counter_offset = 5

    # Build a fake UL data frame
    payload = b"\x0C\x00\x0F\x00\x01"  # door closed
    mic = b"\xAA\xBB\xCC\xDD"
    raw = build_frame(0xE0, 0x54, SENSOR_MAC, 0x07, 0x2D,
                      mic, payload, session.session_key, counter=2)

    result = session.handle_rx(raw)
    assert result is not None
    assert result.payload == payload
    assert result.mic == mic
    assert result.interpretation == "DOOR CLOSED"


def test_handle_rx_ignores_wrong_mac():
    """In ACTIVE state, frames from unknown MACs should be ignored."""
    from superlink.decoder import build_frame

    gw_mac = bytes.fromhex("AABBCCDDEEFF")
    session = GatewaySession(gw_mac=gw_mac, pairing_key=DEFAULT_PAIRING_KEY)
    session.state = State.ACTIVE
    session.session_key = bytes(range(32))
    session.sensor_mac = SENSOR_MAC
    session._ul_counter_offset = 5

    wrong_mac = bytes.fromhex("112233445566")
    raw = build_frame(0xE0, 0x54, wrong_mac, 0x07, 0x2D,
                      b"\x00" * 4, b"\x00" * 5, session.session_key, counter=2)

    result = session.handle_rx(raw)
    assert result is None
```

- [ ] **Step 10: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py::test_handle_ul_data_in_active_state -v`

Expected: FAIL — `AttributeError: 'GatewaySession' object has no attribute 'handle_rx'`

- [ ] **Step 11: Implement handle_rx**

Add to `GatewaySession` class:

```python
def handle_rx(self, raw: bytes) -> SuperLinkFrame | None:
    """Process a received frame based on current state.

    Args:
        raw: Raw frame bytes from HAL.

    Returns:
        Decoded frame if successfully processed, None otherwise.
    """
    frame = parse_frame(raw)
    if frame is None:
        return None

    if self.state == State.ACTIVE:
        return self._handle_active(frame)
    elif self.state == State.BEACONING:
        return self._handle_beaconing(frame)

    return None

def _handle_active(self, frame: SuperLinkFrame) -> SuperLinkFrame | None:
    """Handle frames in ACTIVE state — decrypt UL data."""
    if self.sensor_mac and frame.mac != self.sensor_mac:
        return None
    if self.session_key is None:
        return None
    if frame.dctrl not in (0x54, 0x44, 0x40):
        return None

    key = self.session_key
    if frame.dctrl == 0x40:
        key = self.pairing_key

    frame = decrypt_frame(frame, key, ul_counter_offset=self._ul_counter_offset)
    log.info("RX %s seq=%02X.%02X %s",
             format_mac(frame.mac), frame.seq_hi, frame.seq_lo,
             frame.interpretation or frame.payload.hex() if frame.payload else "?")
    return frame

def _handle_beaconing(self, frame: SuperLinkFrame) -> SuperLinkFrame | None:
    """Handle frames in BEACONING state — look for ConnectionReq."""
    # TODO: Parse ConnectionReq, extract sensor pubkey, transition to DH_EXCHANGE
    # This requires knowing the ConnectionReq frame format (capture needed)
    log.debug("RX in BEACONING: dctrl=0x%02X from %s (not yet handled)",
              frame.dctrl, format_mac(frame.mac))
    return None
```

- [ ] **Step 12: Run all tests**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py -v`

Expected: All PASS

- [ ] **Step 13: Commit**

```bash
git add tools/sx1302/superlink/gateway.py tests/test_gateway.py
git commit -m "feat: add gateway state machine with ACTIVE state frame handling"
```

---

### Task 6: Gateway CLI Entry Point

**Files:**
- Modify: `tools/sx1302/superlink/gateway.py`

- [ ] **Step 1: Write test for CLI argument parsing**

Add to `tests/test_gateway.py`:

```python
def test_parse_args_required_mac():
    """--mac is required."""
    from superlink.gateway import parse_gw_args
    with pytest.raises(SystemExit):
        parse_gw_args([])


def test_parse_args_defaults():
    """Defaults should be sensible."""
    from superlink.gateway import parse_gw_args
    args = parse_gw_args(["--mac", "AA:BB:CC:DD:EE:FF"])
    assert args.mac == "AA:BB:CC:DD:EE:FF"
    assert args.beacon_interval == 240
    assert args.log is None
    assert args.verbose is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py::test_parse_args_required_mac -v`

Expected: FAIL — `ImportError: cannot import name 'parse_gw_args'`

- [ ] **Step 3: Implement parse_gw_args and main**

Add to the end of `tools/sx1302/superlink/gateway.py`:

```python
import argparse
import csv
import sys


def parse_gw_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse gateway CLI arguments."""
    parser = argparse.ArgumentParser(
        description="SuperLink standalone gateway"
    )
    parser.add_argument(
        "--mac", required=True, metavar="MAC",
        help="Gateway MAC to advertise (e.g. AA:BB:CC:DD:EE:FF)",
    )
    parser.add_argument(
        "--beacon-interval", type=float, default=240, metavar="SEC",
        help="Seconds between beacon TX (default: 240)",
    )
    parser.add_argument(
        "--log", metavar="FILE.csv",
        help="Log all RX/TX frames to CSV file",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print raw hex and crypto details",
    )
    return parser.parse_args(argv)


def main():
    args = parse_gw_args()

    # Parse MAC
    try:
        gw_mac = bytes.fromhex(args.mac.replace(":", "").replace("-", ""))
        if len(gw_mac) != 6:
            raise ValueError("MAC must be 6 bytes")
    except ValueError as e:
        print(f"Error: invalid --mac: {e}", file=sys.stderr)
        sys.exit(1)

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    from .hal import SX1302, BEACON_FREQ_HZ

    session = GatewaySession(
        gw_mac=gw_mac,
        pairing_key=bytes.fromhex(
            "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
        ),
        beacon_interval=args.beacon_interval,
    )

    # CSV logging
    csv_file = None
    csv_writer = None
    if args.log:
        csv_file = open(args.log, "a", newline="")
        csv_writer = csv.writer(csv_file)
        if csv_file.tell() == 0:
            csv_writer.writerow([
                "timestamp", "direction", "state", "mac", "seq",
                "dctrl", "size", "payload", "interpretation",
            ])

    hal = None
    try:
        hal = SX1302()
        log.info("Starting SX1302 concentrator...")
        hal.start()
        log.info("Concentrator started (HAL %s)", hal.version())

        session.start()
        log.info("Gateway MAC: %s — beaconing on %.1f MHz",
                 format_mac(gw_mac), BEACON_FREQ_HZ / 1e6)

        while True:
            # Send beacon if due
            if session.beacon_due():
                beacon = session.build_beacon()
                hal.send(BEACON_FREQ_HZ, beacon)
                log.info("BEACON TX %.1f MHz (%d bytes)",
                         BEACON_FREQ_HZ / 1e6, len(beacon))

            # Poll for RX packets
            for pkt in hal.receive():
                if not pkt.crc_ok:
                    continue
                frame = session.handle_rx(pkt.payload)
                if frame and csv_writer:
                    from datetime import datetime, timezone
                    csv_writer.writerow([
                        datetime.now(timezone.utc).isoformat(),
                        frame.direction,
                        session.state.value,
                        format_mac(frame.mac),
                        f"{frame.seq_hi:02X}.{frame.seq_lo:02X}",
                        f"{frame.dctrl:02X}",
                        len(pkt.payload),
                        frame.payload.hex() if frame.payload else "",
                        frame.interpretation or "",
                    ])
                    csv_file.flush()

            time.sleep(0.01)

    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        if hal:
            hal.stop()
        if csv_file:
            csv_file.close()
```

- [ ] **Step 4: Run tests**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py -v`

Expected: All PASS

- [ ] **Step 5: Add superlink-gw entry point script**

Create a launcher script alongside the existing `superlink-sniff`:

```bash
# Check what superlink-sniff looks like
cat tools/sx1302/superlink-sniff
```

Then create `tools/sx1302/superlink-gw` matching the same pattern:

```python
#!/usr/bin/env python3
"""SuperLink standalone gateway."""
from superlink.gateway import main
main()
```

Make it executable:

```bash
chmod +x tools/sx1302/superlink-gw
```

- [ ] **Step 6: Commit**

```bash
git add tools/sx1302/superlink/gateway.py tools/sx1302/superlink-gw tests/test_gateway.py
git commit -m "feat: add gateway CLI entry point (superlink-gw)"
```

---

### Task 7: End-to-End Integration Test (State Machine + Crypto)

**Files:**
- Modify: `tests/test_gateway.py`

- [ ] **Step 1: Write test for full DH session establishment**

This test simulates both sides of the DH exchange to verify our crypto produces valid session keys:

```python
def test_dh_full_exchange():
    """Simulate sensor + gateway DH exchange, verify shared session key."""
    from superlink.crypto import (
        generate_keypair, compute_shared_secret, derive_session_key,
    )

    # Gateway generates keypair
    gw_priv, gw_pub = generate_keypair()

    # Sensor generates keypair
    sensor_priv, sensor_pub = generate_keypair()

    # Both compute shared secret
    gw_shared = compute_shared_secret(gw_priv, sensor_pub)
    sensor_shared = compute_shared_secret(sensor_priv, gw_pub)
    assert gw_shared == sensor_shared

    # Gateway derives session key (is_initiator=False: first=local, second=remote)
    gw_session_key = derive_session_key(gw_shared, gw_pub, sensor_pub)

    # Sensor derives session key (is_initiator=True: first=remote, second=local)
    sensor_session_key = derive_session_key(sensor_shared, gw_pub, sensor_pub)

    # Both must derive the same key
    assert gw_session_key == sensor_session_key
    assert len(gw_session_key) == 32
```

- [ ] **Step 2: Run test**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py::test_dh_full_exchange -v`

Expected: PASS

- [ ] **Step 3: Write test for encrypt-then-decrypt across gateway/sensor boundary**

```python
def test_sensor_frame_decrypted_by_gateway():
    """A frame encrypted with the session key should be decryptable by the gateway."""
    from superlink.crypto import (
        generate_keypair, compute_shared_secret, derive_session_key,
    )
    from superlink.decoder import build_frame

    # Establish session
    gw_priv, gw_pub = generate_keypair()
    sensor_priv, sensor_pub = generate_keypair()
    shared = compute_shared_secret(gw_priv, sensor_pub)
    session_key = derive_session_key(shared, gw_pub, sensor_pub)

    # Sensor builds a UL data frame
    sensor_mac = SENSOR_MAC
    payload = b"\x0C\x00\x0F\x00\x01"  # door closed
    mic = b"\x11\x22\x33\x44"
    seq_hi = 0x06
    counter_offset = 5
    counter = seq_hi - counter_offset  # = 1

    raw = build_frame(0xE0, 0x54, sensor_mac, seq_hi, 0x99,
                      mic, payload, session_key, counter)

    # Gateway receives and decrypts
    gw = GatewaySession(gw_mac=bytes(6), pairing_key=DEFAULT_PAIRING_KEY)
    gw.state = State.ACTIVE
    gw.session_key = session_key
    gw.sensor_mac = sensor_mac
    gw._ul_counter_offset = counter_offset

    result = gw.handle_rx(raw)
    assert result is not None
    assert result.payload == payload
    assert result.mic == mic
```

- [ ] **Step 4: Run test**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/test_gateway.py::test_sensor_frame_decrypted_by_gateway -v`

Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `cd /Volumes/Secondary/superlink && python -m pytest tests/ -v`

Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add tests/test_gateway.py
git commit -m "test: add end-to-end DH exchange and frame decrypt integration tests"
```

---

## Remaining Work (Capture-Dependent)

The following cannot be implemented until we capture real handshake frames from the Ubiquiti gateway using the keyhook + sniffer. Each item below becomes a new task once the corresponding capture data is available:

1. **Beacon frame payload** — Capture a real beacon on 927.6 MHz to determine the payload format. Update `build_beacon()` to match.

2. **ConnectionReq parsing** — Capture a factory-default sensor's ConnectionReq to map the byte layout. Implement `_handle_beaconing()` to extract the sensor's Curve25519 public key.

3. **ConnectionRsp building** — Once we know the format, implement the gateway's response frame containing our public key + challenge + channel map.

4. **Challenge authentication** — Capture the challenge frames to determine the exact computation. We know it uses `crypto_secretbox` with "UBNU"/"UBNV" nonces, but need the exact key derivation and payload format.

5. **KDF context bytes** — Capture the `additional_data` and `extra_context` parameters fed into the BLAKE2b KDF. Without these, `derive_session_key()` will produce a wrong key.

6. **DL ACK frames** — Implement `_handle_active()` to send DL ACK (dctrl=0x63) after receiving UL data. Format: 16B frame (10B header + 4B MIC + 2B payload). The 2B payload content needs capture verification.

7. **lgw_pkt_tx_s struct verification** — Verify the ctypes struct layout matches the actual `loragw_hal.h` on the RPi before first TX test.
