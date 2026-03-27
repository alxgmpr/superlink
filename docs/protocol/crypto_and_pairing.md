# SuperLink Encryption & Pairing

## Overview

SuperLink uses **libsodium** (NaCl) for all cryptography. The protocol has
two layers: an initial pairing phase using a hardcoded pre-shared key, then
ephemeral session keys established via Curve25519 Diffie-Hellman.

## Crypto Primitives (from libsodium imports in lorabrd)

| Function | Algorithm | Purpose |
|----------|-----------|---------|
| `crypto_scalarmult` | Curve25519 ECDH | Session key agreement |
| `crypto_scalarmult_base` | Curve25519 | Generate DH public key from private |
| `crypto_secretbox_easy` | XSalsa20-Poly1305 | Authenticated encryption (256-bit key, 192-bit nonce, 128-bit MAC) |
| `crypto_secretbox_open_easy` | XSalsa20-Poly1305 | Authenticated decryption |
| `crypto_stream_xor` | XSalsa20 | Stream encryption (no authentication) |
| `crypto_generichash_*` | BLAKE2b | Hashing, key derivation |
| `PKCS5_PBKDF2_HMAC` | PBKDF2-SHA256 | Key derivation from password/secret |
| `sodium_memzero` | — | Secure memory wipe |

## Hardcoded Default Key

The gateway's `lorabrd` binary contains two 32-byte constants in `.rodata`
that are byte-added together to produce the default pairing key:

```
key_source_1: d1696891981946010ea175deef9b4bab495381e41a990de5e20216d8c37f1886
key_source_2: 7655d56e1c055d563b28b4307e86d93b6a9003469a4b36d828c2080241dd1538

default_key = key_source_1[i] + key_source_2[i] (mod 256) for each byte i

default_key: 47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe
```

### Key Stability
- **Confirmed identical** across firmware v1.7.0 and v1.9.0
- Located in `lorabrd` at `.rodata` offsets (v1.9.0: 0xaaa90, 0xaaab0; v1.7.0: 0xa7a60, 0xa7a80)
- This is a symmetric pre-shared key — both gateway and sensors must know it

### Key Derivation Code (decompiled from FUN_000504ba)
```c
// Simplified pseudocode
void derive_default_key(struct device *dev) {
    uint8_t buf1[32], buf2[32];
    memcpy(buf1, KEY_SOURCE_1, 32);  // from .rodata
    memcpy(buf2, KEY_SOURCE_2, 32);  // from .rodata

    // Byte-wise addition
    for (int i = 0; i < 32; i++) {
        buf2[i] += buf1[i];
    }

    dev->default_key = buf2;  // 32-byte result
    assert(len(dev->default_key) == EXPECTED_KEY_SIZE);
}
```

### Controller Override
The string `setDevsDefaultKey` in the binary indicates the UniFi Protect
controller can push a custom key to replace the hardcoded default. Sensors
that have been adopted and received a custom key will reject the hardcoded
default. Factory-reset sensors should revert to the hardcoded key.

## Pairing / Connection Flow

### Packet Types (from C++ RTTI symbols)

**Plaintext packets** (use `PlainHeader`):
1. `Beacon` — Gateway broadcasts presence, timing, channel info
2. `Discovery` — Sensor announces itself, looking for a gateway
3. `ConnectionReq` — Sensor requests connection to gateway
4. `ConnectionRsp` — Gateway responds with DH public key + challenge
5. `ConnectionChallenge` — Authentication challenge
6. `ChallengeReq` — Challenge request with device DH public key
7. `ChallengeRsp` — Challenge response

**Encrypted packets** (use `SecureHeader`):
8. `Data` — Sensor readings, commands (XSalsa20-Poly1305)
9. `KeyRenewReq` — Session key rotation request
10. `KeyRenewRsp` — Session key rotation response
11. `SwitchClassA/B/CReq` — Change operating mode
12. `SwitchClassA/B/CRsp` — Mode change confirmation
13. `ChMap` — Channel assignment map

### Connection Sequence

```
Gateway                              Sensor
   |                                    |
   |--- Beacon (plaintext) ------------>|  Broadcast on all channels
   |                                    |
   |<--- Discovery (plaintext) ---------|  Sensor searching for gateway
   |                                    |
   |<--- ConnectionReq (plaintext) -----|  Contains: sensor MAC, capabilities
   |                                    |
   |--- ConnectionRsp (plaintext) ----->|  Contains: gateway DH pubkey,
   |                                    |           challenge, channel map
   |                                    |
   |<--- ChallengeReq -----------------|  Contains: sensor DH pubkey,
   |                                    |           challenge response
   |                                    |           (authenticated with default_key)
   |                                    |
   |--- ChallengeRsp ----------------->|  Challenge verification
   |                                    |
   |  [DH key exchange completes]       |
   |  shared = Curve25519(my_priv,      |
   |                      their_pub)    |
   |                                    |
   |  [Session key derived via BLAKE2b] |
   |  session_key = BLAKE2b(shared ||   |
   |    pub_A || pub_B || context)      |
   |                                    |
   |=== Encrypted channel established ==|
   |                                    |
   |<-- Data (encrypted) --------------|  Sensor readings
   |--- Data (encrypted) ------------->|  Commands, acks
   |                                    |
   |<-> KeyRenewReq/Rsp (encrypted) <->|  Periodic key rotation
```

### DH Session Key Derivation (decompiled from FUN_0003af5a)

```c
// Simplified pseudocode
void establish_session(DhSession *session,
                       vector<uint8_t> *remote_pubkey,
                       vector<uint8_t> *extra_context) {

    assert(remote_pubkey.size() == 32);  // Curve25519 public key
    assert(session->local_privkey.size() == 32);

    // Store remote public key
    session->remote_pubkey = *remote_pubkey;

    // Compute shared secret via Curve25519
    uint8_t shared[32];
    crypto_scalarmult(shared, session->local_privkey, session->remote_pubkey);

    // Order public keys based on initiator flag
    vector *first_pub, *second_pub;
    if (session->is_initiator) {
        first_pub = &session->remote_pubkey;
        second_pub = &session->local_pubkey;
    } else {
        first_pub = &session->local_pubkey;
        second_pub = &session->remote_pubkey;
    }

    // Derive session key via BLAKE2b
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, 32);
    crypto_generichash_update(&state, shared, 32);
    crypto_generichash_update(&state, *first_pub, 32);
    crypto_generichash_update(&state, *second_pub, 32);
    crypto_generichash_update(&state, session->additional_data, ...);
    crypto_generichash_update(&state, extra_context, ...);
    crypto_generichash_final(&state, session_key, 32);

    sodium_memzero(shared, 32);  // Wipe shared secret
}
```

## Data Encryption

Two encryption modes identified:

### 1. Authenticated Encryption (important messages)
- **Algorithm**: `crypto_secretbox_easy` = XSalsa20-Poly1305
- **Key**: 256-bit session key from DH exchange
- **Nonce**: 192-bit (24 bytes) — likely derived from frame counter
- **MAC**: 128-bit Poly1305 authentication tag
- **Used for**: Management messages, key renewal, sensitive data

### 2. Stream Encryption (lightweight/streaming data)
- **Algorithm**: `crypto_stream_xor` = XSalsa20 (no authentication)
- **Key**: 256-bit session key
- **Nonce**: 192-bit
- **No MAC**: Faster but no integrity protection
- **Used for**: Frequent sensor readings, status updates

## What's Visible to a Passive Sniffer

### Cleartext (no keys needed)
- Beacon frames — gateway ID, timing, channel info, network presence
- Discovery frames — sensor IDs, capabilities
- Connection setup — sensor MACs, DH public keys
- Channel assignments
- Traffic timing, frequency patterns, signal strength
- Traffic volume analysis (who talks when, how much)

### Encrypted (need session key)
- All sensor data (motion, entry, environmental)
- Management commands
- Key renewal messages

## Impersonating a Gateway

With the hardcoded default key, it is possible to impersonate a SuperLink
gateway and have factory-default sensors pair with you:

1. **Broadcast beacons** on the correct channels (see channel plan)
2. **Accept ConnectionReq** from a sensor
3. **Generate Curve25519 keypair** and send ConnectionRsp
4. **Pass the challenge** using the default key for authentication
5. **Complete DH exchange** — you now share a session key with the sensor
6. **Send ChMap** to assign channels
7. **Decrypt/encrypt data** using the session key

### Limitations
- Sensors previously adopted by a real gateway may have had their key
  changed via `setDevsDefaultKey` — they won't pair with the default key
- Factory-reset sensors should revert to the default key
- You need to implement enough of the protocol to keep the sensor connected
  (beacons, keepalives, acks)

## Attack Surface Summary

| Attack | Feasible? | Notes |
|--------|-----------|-------|
| Passive sniff (metadata) | Yes | See headers, timing, MACs |
| Passive sniff (data) | No | XSalsa20-Poly1305 with ephemeral keys |
| Impersonate gateway | Yes* | *Factory-default sensors only, using hardcoded key |
| MITM existing session | No | DH pubkeys authenticated via pre-shared key |
| Replay attack | Unlikely | Nonces/frame counters prevent replay |
| Brute force session key | No | 256-bit Curve25519 + BLAKE2b KDF |
| Extract key from sensor | Maybe | Requires physical access, JTAG/SWD |
