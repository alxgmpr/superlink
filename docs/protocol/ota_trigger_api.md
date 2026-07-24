# Forcing SuperLink sensor OTA via the UniFi Protect API

How to trigger a firmware install (upgrade **or** arbitrary-version downgrade) on a
SuperLink sensor programmatically, driving the UniFi Protect controller's REST API.
This is the autonomous OTA-cycling lever — it bypasses the dashboard's gating
(the UI only offers "update to latest" and a conditionally-shown "Revert").

Discovered 2026-07-23 by reverse-engineering the Protect controller bundle
(`service.js`) + the loaded frontend JS. Complements `ota_update_protocol.md`
(the LoRa wire protocol the controller then speaks to the sensor).

## Console + auth

- Console (UniFi OS): `https://10.1.10.1` — "Gompper Sage" UCG-Fiber. Protect at
  `/protect/`, API under `/proxy/protect/api/`.
- **Auth = the browser's logged-in session cookie** (no separate API key needed).
  Mutations (POST/PATCH) require a CSRF token: read it from the **`x-csrf-token`
  response header** of any GET, echo it back as the `X-CSRF-Token` request header.
  (Do not log the token.)
- Target sensor: `USL Entry`, id **`6a612d4801520a03e4027674`**, mac `9041B22E9A53`.

## Endpoints

| Method | Path (under `/proxy/protect/api`) | Purpose |
|---|---|---|
| GET  | `/sensors/{id}` | State: `firmwareVersion`, `fwUpdateState` (`upToDate`/`updateAvailable`/`updating`/`failed`), `isConnected`, `uptime`, `latestFirmwareVersion`, `previousFirmwareVersion`. |
| POST | `/sensors/{id}/update` | Update to **latest** only (empty body → `devices.update.latest`). No-op if already on latest. |
| GET  | `/devices/{id}/fw-revert-options` | Returns `{previousFirmwareVersion, previousFirmwareUrl}` — the downgrade target + its `.ota` URL. **Available even when the sensor object's `previousFirmwareUrl` field is null and the UI hides the Revert button.** |
| POST | `/devices/{id}/update-by-url` | **The version-forcing lever.** Body `{"url": "<.ota url>"}` → controller downloads that `.ota` and pushes it to the sensor, **no version check** (revert, re-flash, or sidegrade to any URL). |
| POST | `/sensors/{id}/reboot` | Reboot the sensor. |

Note the path split: firmware-file/revert ops are under **`/devices/{id}/...`**;
per-model ops are under `/sensors/{id}/...`. `PATCH /sensors/{id}` **ignores**
firmware fields (`latestFirmwareVersion`, `fwUpdateState` are read-only → 200 but no
effect), so you can't force a version by writing those.

## Recipes

**Upgrade to latest** (when `fwUpdateState==updateAvailable`):
```
POST /proxy/protect/api/sensors/{id}/update      (X-CSRF-Token, empty body)
```

**Force any version (revert/downgrade/re-flash):**
```
GET  /proxy/protect/api/devices/{id}/fw-revert-options   -> {previousFirmwareUrl}
POST /proxy/protect/api/devices/{id}/update-by-url
     headers: X-CSRF-Token, Content-Type: application/json
     body:    {"url": "<previousFirmwareUrl or any usl-* .ota url>"}
```
The `.ota` URLs come from `fw-download.ubnt.com/data/usl-entry/…` (also surfaced by
`fw-revert-options`). Local copies of usl-entry 1.0.0/1.1.0/1.1.1/1.2.0 are in
`firmware/dumps/`.

## State machine (observed)

`upToDate` → *(trigger)* → `updating` (LoRa chunk transfer, **~2.5 min** clean) →
sensor **reboots + bootloader decrypts/installs + app boots, all in <7 s** →
`fw` flips + `fwUpdateState=upToDate`, `uptime` resets. During `updating` the sensor
pauses telemetry so `uptime` reads stale. `isConnected` does **not** flip at normal
poll granularity because the reboot is sub-7s. On failure → `failed` (sensor stays on
the old, still-installed version — no brick).

## Gotchas

- **Detach any J-Link before triggering.** An attached/halted debugger freezes the
  sensor CPU → `isConnected:false` → OTAs fail with "poor SuperLink connection".
  See [[feedback_swd_only_after_ota_complete]] / [[ota_key_swd_during_ota_negative]].
- A stuck `updating` that won't finish is usually the sensor left halted (SWD killed
  mid-dump) — reboot the sensor (`POST /sensors/{id}/reboot` or the button) to clear it.
- `update-by-url` re-flashing the **same** version may be a sensor-side no-op (bootloader
  anti-rollback / same-version skip is untested); use a different version to be sure a
  decrypt/install actually runs.
