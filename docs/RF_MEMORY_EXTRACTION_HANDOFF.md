# SuperLink RE — RF memory-extraction handoff

Continues the OpenSuperLink RE. **Read this whole file first**, plus the linked
docs and memories. Prior handoff `docs/ADOPTION_COMMIT_HANDOFF.md` is resolved
(adoption is solved). Work branch: **`rf-memory-extraction`** (pushed).

## Mission
Extract sensor memory (session/adoption keys, ideally the OTA decrypt key) from
a paired SuperLink motion sensor. Two fronts:
1. **RF path** — find an over-the-air primitive that discloses or corrupts
   sensor memory. App-message layer is exhausted (negative); the live lead is
   the **OTA firmware-chunk write path** (below).
2. **SWD path (ground truth)** — dump the sensor's SRAM over J-Link to read the
   live keystore. Proven to work; currently blocked on using the right J-Link
   connection mode (see "SWD status").

## State of play (what's DONE — don't redo)
- **Adoption: SOLVED & merged to `main` (PR #4).** The Pi/SX1302 gateway
  (`superlink-gw`) adopts a factory-reset sensor end-to-end and holds an
  operational session. Root cause was the `0x63` ACK sequencing (echo the
  sensor's `0x54` ADOPT_RESPONSE `seq_hi`, `seq_lo+1`) + the dual-key reconnect
  (fallbackKey = `0x62/0x42` transport, primary addDevice.key = session-KDF
  context, rotate only on observing adopted-form `0x40`). See
  `docs/protocol/adoption_commit_mechanism.md` + decoded transcript
  `captures/live/bridge_adopt_fresh_pass2_DECODED.txt`.
- **Full app-layer fuzzing suite built** (all in `tools/sx1302/superlink/`,
  driven by the sustained command-window exchange):
  - `--sweep` PROPERTY_REQUEST (property-id space) — **negative** (undefined ids
    → empty; defined ids return real values, so the mechanism is confirmed).
  - `--msg-sweep` message-id/opcode space — **negative** (undefined opcodes →
    graceful REQUEST_STATUS_RESPONSE).
  - `--ping-probe` PING over-read — **negative** (echo is length-exact).
  - `--fuzz` crafted-frame harness (length-field over-reads, oversized values,
    undefined opcodes) — **negative on disclosure**, BUT found the OTA lead.
- **Key persistence: `--reconnect`** — caches committed addDevice keys to
  `/tmp/superlink_adopt.json` on commit and rejoins an adopted sensor after a
  gateway restart. **No factory-reset needed between restarts.** Verified.
- **`--keep-awake`** — continuous PING loop holds the sensor in its command
  window so the CPU never deep-sleeps. Verified (100+ continuous PING/RSP).
- **SWD proven** — J-Link attaches to the RDP1-locked STM32WLE5 and dumps 64 KB
  SRAM. Keystore located in prior dumps: see `docs/protocol/sensor_sram_keystore.md`
  (pairing key `47be3dff` @`0x200002e0`; addDevice.key @`0x20001298`;
  fallbackKey @`0x200012b8` — offsets vary per boot, so SEARCH the dump for a
  known key rather than reading a fixed address).

## THE live RF lead — OTA firmware-chunk write path
The `--fuzz` run found: an unsolicited **`FIRMWARE_CHUNK_RESPONSE` (msgId 0x11)**
— sent as a normal DL `0x74` command — **drives the sensor's OTA state machine
without a `FIRMWARE_UPDATE_START`**. The sensor replies `FIRMWARE_CHUNK_REQUEST`
(0x10) `size=0xeb offset=0 status=1(ERROR)`, repeatedly. Wire format
(messages.ts module 41118): `FIRMWARE_CHUNK_RESPONSE = [0x11][tag][offset:4 BE]
[chunk…]`. **`offset` and `chunk` are attacker-controlled** → candidate
OOB-write into the sensor's OTA staging buffer. The sensor rejected a garbage
chunk (validates), but WHERE offset/chunk data lands *before* the check is the
target. This is the best RF-memory primitive found. Investigate via the
SWD-instrumented differential dump (below). NOTE: this is a WRITE path —
aggressive testing risks bricking the single sensor; go carefully.

## SWD status — SOLVED 2026-07-23 (attach-no-reset proven)
Live keystore extraction over SWD is **done**. `tools/sensor_swd/live_dump.sh`
(with `attach_dump.jlink`) attaches to the running sensor with no reset and reads
the current committed keys. Ground truth: live `primary=fa806bc3…`/`fallback=e65a1a23…`
from the Pi's `superlink_adopt.json` both found at `0x20001298`/`0x200012b8`.
Recipe + why in `docs/protocol/sensor_sram_keystore.md` ("Live extraction method").
Key facts: (a) `--keep-awake` keeps the SWD-AP powered; (b) generic `Cortex-M4`
device + never `r`; (c) STM32 STOPs between PING slots so you must HAMMER the
attach (~170 shots) to catch a window — a power-cycle's boot window is easiest;
(d) NRST is unwired so a missed attach can't reset the sensor (adoption survives).
The remaining SWD gap: OTA decrypt key is NOT in SRAM (RDP1 flash), so SWD gives
session/adopt keys only.

## (historical) SWD blocker & the CORRECT method (my mistake — don't repeat)
J-Link (`/usr/local/bin/JLinkExe`, on the Mac) attaches to the sensor and dumps
SRAM. Prior dumps `captures/sensor_ram*.bin` (gitignored) contain the keystore.
The blocker this session: I kept letting J-Link fall back to **connect-under-
reset**, which resets the core — that (a) clears the live keystore to a boot
state and (b) is fundamentally incompatible with an active RF session (reset
halts the radio task). **Use a plain ATTACH instead: halt the running core in
place, no reset.** With `--keep-awake` holding the CPU up, a proper attach lands
on the running app with keys resident. Figure out the exact JLinkExe/JLink
incantation for attach-only (no reset-on-connect) — e.g. JLinkGDBServer in
attach mode + `monitor halt`, or the J-Link connect-strategy setting; do NOT use
`r`/connect-under-reset. Watch the IWDG (dump fast after halt). The prior working
`sensor_ram_paired.bin` was a plain attach that caught a natural wake window.

### The differential-dump experiment (once attach-no-reset works)
1. `superlink-gw --reconnect --keep-awake` holds the sensor awake and adopted.
2. Via the gateway, send a crafted `FIRMWARE_CHUNK_RESPONSE` with a distinctive
   marker chunk (`DEADBEEF…`) at a chosen `offset` (add a small mode/CLI hook,
   or extend the fuzz harness).
3. Plain-attach + `savebin /tmp/x.bin 0x20000000 0x10000` immediately after.
4. Diff / search for the marker → learn the OTA buffer address and whether
   `offset` controls the write address. If it reaches `0x1298`-class addresses,
   that's OOB-write-to-keystore.
Also do the simpler win first: with `--keep-awake` running, plain-attach + dump
+ `grep` the SRAM for the current addDevice.key (from `/tmp/superlink_adopt.json`)
to prove live keystore extraction over SWD.

## Bench access
- **Pi gateway (SX1302)**: `ssh -i ~/.ssh/id_ed25519_pi alex@sx1302.local`
  (pw also `alex`). Python `~/superlink-venv/bin/python3`, package `~/superlink/`.
  Deploy: `cd tools/sx1302 && scp -i ~/.ssh/id_ed25519_pi superlink/*.py
  alex@sx1302.local:~/superlink/superlink/`. Run (background over SSH; restart
  loses in-RAM keys unless `--reconnect`):
  `~/superlink-venv/bin/python3 -u superlink-gw --mac AA:BB:CC:DD:EE:01
  --kdf-context c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db
  [--reconnect] [--keep-awake|--fuzz|--sweep|--msg-sweep|--ping-probe] --verbose`
  Concentrator must be reset first: `sudo ~/sx1302_hal/tools/reset_lgw.sh start`.
- **Sensor**: MAC `90:41:B2:2E:9A:53`, AcSiP ST50HE = STM32WLE5, **RDP1**
  (flash locked, SRAM readable). Sleepy battery device; adoption persists in
  flash across power-cycle/reboot (only a FACTORY reset clears it). Default
  adoption key `c5923a86…` (global constant, not per-device). Pairing key
  `47be3dff…`. networkId `0x048f`.
- **J-Link**: `/usr/local/bin/JLinkExe` + `JLinkGDBServer` on the Mac, wired to
  the sensor's J3 SWD (SWDIO=PA13, SWCLK=PA14, NRST=pad44). `device Cortex-M4`,
  `si SWD`, `speed 1000`. `tools/sensor_swd/analyze_ram.py` hunts keys in a dump.
- **Real UniFi bridge** (`lorabrd`): `ubnt@10.1.10.141`, pw
  `zaLsHMDA7IdjmVhR1sFyODonQPfZ6h` (FORCE password auth; `scp -O`). Keyhook:
  `tools/keyhook/`. SSH disabled on bridge reset → re-enable via the
  `reenable-bridge-ssh` skill / Protect web UI.
- **Protect firmware (controller source)**: `firmware/dumps/UNVR-5.0.16-*.bin`,
  squashfs `service.js` (module 41118 messages.ts, 31048 deviceAdopt.ts, 62701
  constants, 17695 properties). Extract per `sensor_sram_keystore.md`.

## Key files
`tools/sx1302/superlink/gateway.py` (state machine, `--reconnect`/`--keep-awake`,
`_persist_adopt_keys`/`load_adopt_keys`), `sweep.py` (PropertySweep/MessageSweep/
PingProbe/FuzzHarness/KeepAwake + `build_fuzz_corpus`), `appmsg.py` (codec),
`adopt.py` (ADOPT/kdf_E). Docs: `docs/protocol/adoption_commit_mechanism.md`,
`sensor_sram_keystore.md`, `superlink_application_layer.md`. Tests: 83 pass, 2
pre-existing `0x42` `test_gateway.py` challenge failures unrelated.

## Relevant memories
`property_request_read_primitive` (fuzz results + OTA lead),
`sensor_st50he_teardown` (SWD/RDP1, keystore located), `adoption_commit_dual_key_model`,
`session_key_kdf`, `next_session_pi_gw_state` (resolved).

## Immediate next steps
1. Solve **attach-no-reset** in JLinkExe (the one real blocker). Prove it by
   `--keep-awake` + attach + dump + grep for the live addDevice.key.
2. Build the OTA differential-dump: crafted `FIRMWARE_CHUNK_RESPONSE` w/ marker
   at varying `offset`, dump, locate → test the OOB-write hypothesis.
3. If SWD stays flaky: the app-layer RF read surface is exhausted; the frame/
   connection-layer parser and the OTA path are the remaining RF surfaces.
