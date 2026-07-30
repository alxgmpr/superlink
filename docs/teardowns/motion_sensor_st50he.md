# Motion Sensor Teardown — AcSiP ST50HE (STM32WLE5) + SWD/RAM Key Extraction

Status as of 2026-07-22. Hands-on bench RE of a UniFi SuperLink motion sensor.

## TL;DR

- The sensor's radio SoC is an **AcSiP ST50HE = STM32WLE5** (Cortex-M4 + integrated
  LoRa radio on one die). Marking `ST50HE / 225E02 / 2539` (wk39 2025).
- It exposes a **UART bootloader console** (J3 pin 1, **921600 8N1**) and a **SWD debug
  port** (J3) — both usable.
- The MCU is **RDP Level 1** (`FLASH_OPTR @0x58004020 = 0x3FFDF6BB`, RDP byte `0xBB`).
  **Flash is not readable** ("Could not read memory") → stock firmware cannot be dumped
  over SWD.
- **But SRAM *is* readable under RDP1.** This is the key opening: runtime secrets
  (session keys, DH state) can be pulled from RAM even though flash is locked.
- Open task: cross-reference a **bridge-captured session key** (`keyhook`) against a
  **fresh sensor RAM dump** to positively locate/prove the live session key in the sensor.

## Hardware

Two-board sandwich, joined by a board-to-board connector:
- **Main sensor board** `11-10546-05`: PIR dome, reed switch (`59170-1-S-00-D`, tamper),
  accelerometer/sensor QFN `U3`, CR123A (3 V) battery contacts, buttons SW1–SW5,
  connectors J2/J3.
- **Radio daughterboard**: the ST50HE module, a spring antenna **and** a U.FL with a
  `CUT` trace between them (can convert to conducted RF into an SX1302 with an attenuator),
  breakout resistors R50/R51/R417/R418/R425/R426/R428.

### Connectors / debug interfaces (main board)
- **J2** = white flip-lock **FPC**. Buzzed out to MCU GPIO: `PB7, PB8, PC1, PC2, PC3,
  PC4 (jumper depopulated), PC5` + GND. Interpretation: PB7/PB8 = I2C1 (sensor bus);
  PC1 = a GPIO/UART candidate. **This is NOT the debug port.** (R452 is just a resistor
  near J3 — there is no "R452 header".)
- **J3** = the 5-pin 1 mm header. Confirmed to carry **SWDIO (PA13)** and **SWCLK (PA14)**,
  plus a **UART console TX on pin 1**, and GND. It does **not** carry NRST or VDD.
- **NRST** = STM32 module **pad 44**. Not on J3. Obtained via **SW3** (reset-adjacent) /
  direct wire to the NRST net. Required for the debugger to attach (see SWD notes).
- ST50H module pinout (AcSiP datasheet): SWDIO=PA13=pad1, SWCLK=PA14=pad2, NRST=pad44,
  BOOT0=pad43, VDD=pad3/55.

## UART bootloader console (J3 pin 1, 921600 8N1)

Found via Saleae Logic 2 (driven over MCP) → raw-CSV export → custom decoder
(`scratchpad/analyze2.py`, `dump.py`). LA channel 0 = probe "wire 1" = **J3 pin 1**.
Verified 78/78 clean frames. Complete boot output (identical every boot):

```
BL 1.0.1
I:0020:00000000
I:0023:00000000
I:0021:00000000
I:0002:00000294        <- 0x564 after a factory-reset hold (was 0x294)
```

- `BL 1.0.1` = a versioned Ubiquiti **bootloader** stage before the app.
- `I:<id>:<hex32>` = persistent state dump (NOT memory addresses). Same 4 ids every boot;
  only `I:0002` changes. `0x294`(660) normal, `0x564`(1380) after a factory-reset hold
  (+720). Signature of persistent counters / backup-register-style state, not addresses.
- **TX-only** — the app prints nothing on this pin (10 s of silence after boot). No
  interactive shell reachable (its RX pin is not broken out to J2/J3). Diagnostic only,
  **not** a firmware-extraction path.

Saleae note: device is an original **Logic** (USB2, fixed threshold). Reliable recipe
for 921600: capture **1 channel @ 24 MS/s** with a **falling-edge trigger on CH0**;
multi-channel high-rate manual captures overrun USB.

## SWD access

- SWD needs only **SWDIO, SWCLK, GND** + a **VTref** reference. VTref is sourced from the
  bench **+3 V rail** (J-Link senses it, does not power the target). VTref read 3.326 V OK.
- **NRST is required to attach** here — because RDP1 forces connect-under-reset. Without
  NRST: `DAP initialized... Active read protection detected... RESET (pin 15) high, but
  should be low... connect under reset failed`. With NRST wired, attach completes.
- The **J-Link firmware must be current** — an ancient V8 (2009) firmware found the core
  but failed the connect; updating it fixed attach.
- Connect as a **generic Cortex-M4** (`-device Cortex-M4`), not `STM32WLE5JC` — the ST
  device script detects RDP and aborts with "Skipping unsecure". Generic connect attaches
  and allows RAM/register reads.

Working command:
```
JLinkExe -device Cortex-M4 -if SWD -speed 1000 -autoconnect 1
```

### RDP result — Level 1
```
mem32 0x58004020 1   -> 58004020 = 3FFDF6BB   (RDP byte 0xBB = Level 1; AA=L0, CC=L2)
mem32 0x08000000 8   -> Could not read memory  (flash read-protected)
mem32 0x20000000 8   -> readable                (SRAM NOT protected)
```
Consequences: **cannot dump stock firmware**; the only route to flash *access* is a
**mass-erase → RDP0**, which is **destructive** (wipes firmware + provisioning, and we
can't read it first). **Do not mass-erase this reference unit** — develop open firmware on
a spare ST50HE / NUCLEO-WL55JC using this same SWD rig instead.

### Attach behavior (important)
Attaching the debugger under RDP1 **halts/locks the CPU** — it drops to LOCKUP
(`PC = 0xFFFFFFFE`) and `Go` cannot resume it. So the firmware does **not** run while the
debugger is attached. **Recovery: `exit` the J-Link session (releases the core) and
power-cycle the sensor** with no active debug session; it then boots and runs normally.
The SWD wires can stay physically connected — RDP1 only reacts to an *active* session.

**SRAM survives the attach** (a warm reset does not clear SRAM, and the locked core never
runs C-startup to zero .bss). So the method is: let the sensor run freely (no debugger),
then attach-and-dump — RAM reflects the state from the instant before attach.

## RAM extraction channel (the real opening)

`savebin <file> 0x20000000 0x10000` dumps all 64 KB (SRAM1+SRAM2). Paired sensors **sleep**
between listening windows → intermittent "Failed to power up DAP"; a **retry loop at
`-speed 1000`** catches a wake window.

Dumps captured (in `captures/`):
- `sensor_ram.bin`      — idle, factory-reset/unpaired
- `sensor_ram2.bin`     — second idle (for diffing)
- `sensor_ram_live.bin` — running/chirping, unpaired
- `sensor_ram_paired.bin` — paired with a real bridge (pre-keyhook session)

### Firmware facts learned from RAM
- **FreeRTOS** — task names `IDLE`, `Tmr Svc`, `defaultTask`, **`radio`**.
- **App code lives ≥ 0x08029000** in flash (highest code pointer 0x08029ab8).
- A large const block `0x200043cc–0x20004e28` is a **Curve25519 precomputation table**
  (radix-2^25.5 limbs: uint32 < 2^28) → libsodium-style table-based X25519/Ed25519. Public,
  not secret.
- Heap uses `0xFACEEDBE` guards; session crypto buffers appear ~`0x20007800–0x20007c00`
  when paired.

Reusable analysis tool (persisted in repo): **`tools/sensor_swd/analyze_ram.py`**
(`uv run --with cryptography python tools/sensor_swd/analyze_ram.py <dump.bin> [--key HEX]`).

### Key-search results
- `ramscan.py`, `ramdiff.py` — maps, strings, entropy, two-dump diff.
- `x25519test.py`, `edtest.py`, `pairan.py`, `livean.py` — X25519/Ed25519 keypair
  self-consistency (priv→pub, and libsodium seed‖pub sk layout), on idle/live/paired dumps.
- **Result: 0 keypair hits on every dump.** Reason: the **session key and DH shared secret
  are symmetric 32-byte blobs** (XSalsa20-Poly1305 + BLAKE2b KDF) — not identifiable by a
  priv→pub test. The ephemeral X25519 private is likely wiped after the shared secret is
  derived, leaving only symmetric material that looks like noise.
- No static identity keypair recoverable from idle/chirping RAM either → keys only
  materialize during an actual bridge-initiated session.

### Device pairing model (corrected)
There is **no user pairing mode**. The sensor emits periodic **chirps**; the **bridge**
hears them and pairs from the dashboard (one click), then waits for the sensor's listening
window to run the handshake. So a live session (hence keys in RAM) requires a real peer.

## OPEN TASK — locate the session key via bridge ground truth

The session key is symmetric, so it can only be positively identified with an external
reference. Plan:

1. On the bridge, run `tools/keyhook/capture_key.sh <bridge_ip>` (default `10.1.1.141`;
   creds baked in; needs `arm-linux-gnueabihf-gcc` + `sshpass`, so run from Linux/Pi).
   It **restarts `lorabrd`** → sensor **re-handshakes** → prints the new session key(s).
2. **Immediately** take a **fresh** sensor RAM dump (retry loop, `-speed 1000`) so it is
   synced to that exact re-handshaked session (the pre-existing `sensor_ram_paired.bin` is
   from a *different* session and won't match).
3. `grep`/search the fresh dump for the captured 32-byte key → **match + address** proves
   live session-key extraction from a read-protected sensor, validated against the bridge's
   own copy.

Caveat: restarting `lorabrd` briefly disrupts the bridge and re-pairs the sensor — expected.
If no match: the sensor may hold the symmetric key in a crypto-core register or split form
not covered by the SRAM dump; adjust accordingly.

### Progress 2026-07-22 — bridge key captured; sensor dump still blocked

- **Bridge-side capture works again.** Pi build host is gone → `keyhook.so` is now
  cross-compiled via an OrbStack Debian `gcc-arm-linux-gnueabihf` container
  (`-marm -fomit-frame-pointer` REQUIRED; Debian defaults to Thumb-2 where r7 is
  the frame pointer and the read() syscall asm needs r7). Deploy/capture via
  `tools/keyhook/deploy_prebuilt.sh` (procd `stop` first — a bare killall respawns;
  busybox has no nohup/setsid so detach with `( … & )` orphan-to-init).
- Bridge is now at **`10.1.10.141`** (SSH re-enabled via the browser Protect
  session — see `docs/gateway_ssh_access.md`).
- Captured this session (`captures/live/bridge_pair_keyhook_20260722.log`):
  DH shared `600b661a…`; **session key `00eca81f68eea6be1b43ccc67c49062689ba2be79a8aa4b4a1446576b3b55b46`**
  (secretbox + xsalsa20 stream, nonce UBNU/UBNV); factory pairing key `47be3dff…`
  (confirms decode).
- **The sensor IS live in this session right now** (hooked lorabrd holding it), so
  key `00eca81f…` is resident in sensor SRAM at this moment.
- **Still blocked on the synced dump:** J-Link only attaches during a reset window,
  and **SW3 is a software GPIO, NOT the NRST net** — so the only catchable window is
  a cold power-up, which wipes SRAM (verified: a power-up-window dump has zero
  FreeRTOS task strings and an all-zero session buffer). Need a **direct momentary
  pull-low on NRST / pad44** (warm reset preserves SRAM) to catch a populated dump
  and prove `00eca81f…` resident. That NRST wire is the next bench task.

## Related memory
See auto-memory `sensor-st50he-teardown`, `session-key-kdf`, `next-session-pi-gw-state`,
`reference-bridge-tooling`, `feedback-debugger-care`.
