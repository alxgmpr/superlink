# ST50HE sensor SRAM keystore (SWD extraction)

The motion sensor's SoC is an AcSiP ST50HE = STM32WLE5, **RDP Level 1**. RDP1
blocks reading internal *flash* over SWD, but **not SRAM** — a debugger can halt
the core and `savebin <f> 0x20000000 0x10000` to pull all 64 KB of live RAM
(`0x20000000`–`0x2000FFFF`). That RAM contains the full crypto keystore. Tooling:
`tools/sensor_swd/analyze_ram.py`. Reference dumps: `captures/sensor_ram*.bin`.

## Located key material (offsets stable across dumps)

| SRAM address | Bytes | Contents |
|---|---|---|
| `0x200002e0` | 32 | **Pairing key** `47be3dff…045c2dbe` — the global UBNT default used for `0x40` discovery + pre-adoption `0x62/0x42` handshake. Constant. |
| `0x20001298` | 32 | **`addDevice.key`** (primary, persistent) — e.g. `236f0651e06043c7…adc46968`. This is the operational-session KDF context; verified to derive the bridge op key `9432ba8e…`. |
| `0x200012b8` | 32 | **`addDevice.fallbackKey`** (persistent) — e.g. `fd0a631f…cd320d6d`. The post-adoption `0x62/0x42` reconnect transport key. Stored immediately after the primary. |

The two `addDevice` keys at `0x1298`/`0x12b8` are the per-adoption secrets a
peer needs to impersonate the controller to this sensor (or to decrypt its
traffic). They survive across the operational session; they change on each fresh
adoption. `c5923a86` (the default adoption key) is *not* resident — it lives in
flash / is derived, consistent with it being a constant the code references.

Other regions of interest (session-varying, high-entropy): `0x2000019c`,
`0x20002ca8`, `0x20003468`, `0x20007800`–`0x20007c00` hold live session/handshake
state and the sensor MAC (`9041b22e9a53`). `0x20001a44` and nearby hold ASCII
debug strings (`[CORE] New session…`).

## Relationship to the RF attack surface

Memory extraction is **demonstrated via SWD** (physical access to the SWD pads).
The equivalent *over-the-air* extraction is unproven: the application-message
layer is bounds-checked (PROPERTY_REQUEST of undefined ids → empty, undefined
opcodes → graceful status, PING → length-exact echo — see
`docs/protocol/adoption_commit_mechanism.md` and the sweeps). A remote read of
these SRAM addresses would require a vulnerability in the connection-handshake /
frame-parsing layer below the app messages, or a memory-corruption exploit —
neither demonstrated.
