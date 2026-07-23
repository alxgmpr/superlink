# SuperLink firmware-OTA protocol (controller ↔ sensor)

Mapped from the Protect controller bundle `usr/share/unifi-protect/app/service.js`
(2026-07-23). Two modules: **41118** (`helpers/applicationLayer/messages.ts` —
MessageId enum + encode/decode) and the **`deviceUpdate`** orchestrator
(subscriber `"loraBridge.device.update"`, source `middleware/devices/loraBridges/
subscribers/`). This is the firmware-*update* path — distinct from `ota_captures.md`
(over-the-air RF captures). Complements `ota_handler_not_in_lorabrd` (the `.ota`
decrypt key is fused in the RDP1 bootloader; controller is a dumb byte relay).

## Message wire formats

All frames: `[messageId:u8][messageTag:u8][payload…]`, payload ≤ **239 B**
(module const `s=239`). The "tag" is the header byte, not a payload field.

| msgId | name | dir | payload layout |
|---|---|---|---|
| 0x0f (15) | FIRMWARE_UPDATE_START | ctl→sensor | `[size:u32 BE]` (6 B total). `size` = **total .ota file size, header included**. No version, no hash, no chunk-size. |
| 0x10 (16) | FIRMWARE_CHUNK_REQUEST | sensor→ctl | `[size:u32 BE][offset:u32 BE][status:u8]` (11 B total). Sensor picks `size` and `offset` every round. |
| 0x11 (17) | FIRMWARE_CHUNK_RESPONSE | ctl→sensor | `[offset:u32 BE][chunk…]`. chunk ≤ **235 B** (239−4); `encodeMessage` throws if larger. |

`FirmwareChunkStatus` (the status byte in CHUNK_REQUEST): `0=CONTINUE`,
`1=ERROR`, `2=COMPLETED`. There is **no** separate UPDATE_COMPLETE/END/ABORT
message — completion and failure are signaled by this status byte.

## State machine (the sensor drives it)

```
ctl:    TX 0x0f | tag | u32be(fileSize)              # enter OTA mode
loop:
  sensor: TX 0x10 | tag | u32be(size) | u32be(offset) | u8(status)
  ctl:    status==0 CONTINUE  -> TX 0x11 | tag | u32be(offset) | pread(fd,size,offset)
          status==2 COMPLETED -> done: wait 5s, TX 0x09 DEVICE_INFO_REQUEST, mark upToDate
          status==1 ERROR     -> abort (fwUpdateState=updateAvailable)
  guard:  cumulative sum(size) <= 2*fileSize  (else "exceeded transfer limit")
          size>0 ; chunk<=235
```

The controller is a **stateless `pread(fd, size, offset)` relay** — it never
computes or tracks "next" offset. The **sensor** requests each `(size, offset)`;
the controller reads that slice of the raw `.ota` file and echoes it back with the
same `offset`. `offset` indexes the whole file **including the 32-byte `.ota`
header** (`magic|fmt|ver|id|len|nonce`). `UPDATE_FIRMWARE_TIMEOUT_MS = 30000`.

## Version gating (important)

- **No RF message carries a firmware version/hash/product id.** UPDATE_START has
  only `size`. The version lives solely inside the encrypted `.ota` header, which
  the controller never reads.
- **All version gating seen is controller-side *policy***: `checkDeviceUpdate`
  uses `semver` against `config.deviceVersions`/cloud and honors a **`force`
  flag** that bypasses the comparison. `deviceUpdate` itself does **no** version
  check — it streams whatever `fwPath` points at, every time it's published.
- ⇒ **The controller can re-push the same image endlessly.** Whether the *sensor
  bootloader* refuses a same/older re-flash (reading the `.ota` `ver`/`id`) is
  NOT in this bundle — **testable on the bench only.**

## Offset/length bounds (controller side)

- `offset`: **no min/max, no EOF, no alignment.** Passed straight to `fs.read`.
  Past-EOF → short/zero-filled read, returned without error.
- `size`: asserted `>0`; upper-bounded only by the 239-B payload cap (chunk ≤235).
- Cumulative requested bytes must stay ≤ `2×fileSize` or the update aborts.

## Attack-surface notes (for the RF write experiments)

- **OOB-offset write (Vector 2):** the sensor uses the CHUNK_RESPONSE `offset` to
  place the chunk in its reassembly/staging buffer. An unsolicited `0x11` alone is
  rejected with `status=ERROR` (sensor not in OTA mode) — so first send a valid
  `0x0f FIRMWARE_UPDATE_START{size}` to enter OTA mode, THEN send `0x11` with an
  attacker-chosen `offset` the sensor never requested. If the sensor trusts
  `offset` without bounding it to the current transfer window → OOB write into RAM
  (pre-signature-check ⇒ RCE-class, independent of the `.ota` crypto). Observe via
  SWD fault regs (CFSR/HFSR/BFAR) + differential SRAM dump.
- **Firmware capture:** since the controller side is a trivial relay, we can push
  the legit `usl-motion-ST50H-1.1.1.ota` ourselves and dump SRAM during the
  bootloader's decrypt→flash step to catch **decrypted firmware in transit**
  (the decrypt key stays locked; we grab its plaintext output). We control timing:
  pause before answering a CHUNK_REQUEST to dump at a known transfer state.
