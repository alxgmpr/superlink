# EMFI RDP-downgrade — plan to extract the SuperLink OTA decrypt key

**Goal:** recover the **per-product OTA stream-decrypt key** (32 B, id `A1126063` =
usl-entry) so we can decrypt current + future usl-entry `.ota` payloads offline.
The key is fused/hidden in the sensor's `BL 1.0.1` bootloader (STM32WLE5, RDP1,
HDP/securable area) — unreachable by SWD (debug port is locked during the secure
boot decrypt; proven, [[ota_key_swd_during_ota_negative]]). The route is **fault
injection to downgrade RDP1→RDP0 at boot, then read main flash over SWD.**

## What a flash dump gives us (the pivot)

RDP0 debug read of `0x08000000…` yields **main flash**: the cleartext app (a prize
on its own) **and the `BL 1.0.1` bootloader code**. Reading the BL is the real
unlock — it converts "where/how is the key stored?" from a guess into something we
read directly:
- **If the key sits in the main-flash BL region** → we have it, done.
- **If the BL loads the key from the ESE/SFSA securable area** → RDP-downgrade alone
  may not expose that region (securable-area lock is separate from RDP). But we can
  then *read the BL code* to see exactly how it accesses the key and design the next
  step. Either way the dump is mandatory and high-value.

## `.ota` container (decrypt recipe once we have the key)

Mapped from usl-entry 1.0.0/1.1.0/1.1.1/1.2.0 (`docs/protocol/ota_trigger_api.md`
for how to fetch/push them). fmt 4, header magic `E72609EA`, footer `E05C4DDB`:

| off | field | |
|---|---|---|
| 0x00 | magic `E72609EA` | const |
| 0x04 | fmt=4 | const |
| 0x08 | `00000001` | enc/alg flag (=1) |
| 0x0C | id `A1126063` | **per-product key selector** |
| 0x10 | nonce_len=8 | const → **8-byte nonce ⇒ Salsa20/ChaCha20 family** |
| 0x14 | nonce (8 B) | per-build |
| 0x1C | inner magic `60CCDA46` | const |
| 0x20 | payload_len | `= filesize − 260` |
| 0x24 | **ciphertext** | ends at `filesize − 224`; body entropy 7.998 |
| −224 | signature trailer | `A4DBAC55|len132|type1|…` + `len64|64B sig` + footer |

Decrypt = `stream_cipher(key32, nonce=bytes[0x14:0x1C], ct=bytes[0x24:-224])`.
Confirm Salsa20 vs ChaCha20 (and any KDF over the raw key) from the BL code once dumped.
Signature block = anti-forge only; does NOT affect decryption.

## Target facts (STM32WLE5 / AcSiP ST50HE)

- RDP **Level 1** confirmed: `FLASH_OPTR @0x58004020 = 0x3FFDF6BB` (RDP byte `0xBB`).
  SRAM readable over SWD; flash read = "Could not read memory". NOT L2.
- At reset the flash controller latches the RDP level from the option bytes; that
  latch is the glitch target (make it read as RDP0/`0xAA`).
- No VCAP tap + internal SMPS/LDO smooth VDD ⇒ **EM injection**, not voltage crowbar.
- NRST currently **unwired** on the reference unit → wire it (or trigger off power-on)
  for a clean glitch-timing edge.
- Refs: RM0461 (WLE5 FLASH security: RDP/PCROP/WRP/SFSA/HDP bits), UM2767 (SBSFU),
  AN5156 (security model), AN4992 (SFI). See [[ota_read_flash_not_key]].

## Rig

- **Injector:** PicoEMP (open-source EMFI, HV pulse into a hand-wound EM probe).
- **Timing/trigger:** the FPGA — arm on reset/power-on edge, wait a swept delay,
  fire the PicoEMP pulse. (ChipWhisperer works too but FPGA is fine.)
- **Oracle (automated):** J-Link script reading `0x08000000` → success = returns
  data, fail = "Could not read memory". Binary, scriptable, fast.
- **Positioning:** move the EM probe in XY over the die (flash-ctrl / option-byte
  region). Through-package first; decap only if coupling is too weak.
- **Search space:** delay-after-reset × pulse strength × probe position. Automate the
  sweep; log oracle result per point.

## Procedure

1. **Practice on a sacrificial dev board first** — NUCLEO-WL55JC1 (same STM32WLE5,
   ~$40, easy RDP set/reset via STM32CubeProgrammer) or an ST50HE eval board. Set it
   to RDP1, develop the whole glitch (timing window, pulse, position) where a
   mass-erase costs nothing.
2. Find the reset→option-byte-latch window: sweep delay while pulsing; watch for the
   oracle flipping to "flash readable".
3. Tune pulse strength + position for a repeatable hit (expect ~1–10%/attempt; retry
   in a loop; power-cycle between attempts).
4. Port the tuned parameters to the real ST50HE sensor; dump all of flash.
5. Locate the key: search the BL region for a 32-B blob that decrypts a known `.ota`
   body to a valid ARM image (vector table / low entropy) with `stream(key, nonce)`.
   Cross-check by decrypting a second version with the same key.

## Safety / non-destructive

- **Never write option bytes to RDP0** — that path triggers the **mass-erase**
  (wipes fw + provisioning). We only ever *glitch-read*; RDP stays 1 in the OTP.
- Bad glitches just crash → power-cycle recovers. NRST unwired means a failed
  connect-under-reset can't reset either (harmless).
- Keep the reference sensor for last; prove everything on the dev board.

## Open questions

- Key in main-flash BL region (RDP0 read = done) vs ESE/SFSA securable area (needs a
  second bypass)? → answered by reading the BL code post-dump.
- Salsa20 vs ChaCha20, and is the header key used raw or via a KDF? → read from BL.
- Is `id A1126063` a key selector into a table, or the key itself derived from it? → BL.
