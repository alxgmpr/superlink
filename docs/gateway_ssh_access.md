# Enabling SSH on Ubiquiti Protect Devices via Controller API

Ubiquiti Protect devices (USL-Gateway, cameras, etc.) don't expose SSH directly.
SSH must be enabled through the UniFi Protect controller API, then the device rebooted.

## Prerequisites

- UniFi Protect controller (e.g. Cloud Key, UDM, self-hosted) with admin access
- Device adopted into the controller
- Network access to both controller and device

## Step 1: Authenticate to the Controller

```bash
curl -k -c cookies.txt -D headers.txt \
  -X POST https://<CONTROLLER_IP>/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<ADMIN_USER>","password":"<ADMIN_PASS>"}'
```

Extract the CSRF token from the response headers:
```bash
CSRF=$(grep -i 'x-updated-csrf-token' headers.txt | awk '{print $2}' | tr -d '\r')
```

## Step 2: Enable SSH on the Bridge (Device)

Find the bridge ID for your device. List all bridges:
```bash
curl -k -b cookies.txt \
  https://<CONTROLLER_IP>/proxy/protect/api/bridges
```

Enable SSH on the target bridge:
```bash
curl -k -b cookies.txt \
  -X PATCH https://<CONTROLLER_IP>/proxy/protect/api/bridges/<BRIDGE_ID> \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -d '{"isSshEnabled":true}'
```

## Step 3: Enable SSH on the NVR

The NVR also needs SSH enabled for the setting to propagate:
```bash
curl -k -b cookies.txt \
  -X PATCH https://<CONTROLLER_IP>/proxy/protect/api/nvr \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -d '{"isSshEnabled":true}'
```

## Step 4: Reboot the Device

The SSH setting takes effect after reboot. Trigger via the device's local web API:
```bash
curl -k https://<DEVICE_IP>/api/1.1/reboot
```

Wait ~60 seconds for reboot to complete.

## Step 5: SSH In

Default credentials are `ubnt` with the password shown in the device's local web UI
(accessible at `https://<DEVICE_IP>/` using the same admin credentials).

```bash
ssh ubnt@<DEVICE_IP>
```

## What actually worked (2026-07-22, after a bridge reset)

- **Bridge real IP is `10.1.10.141`** (host subnet), NOT `10.1.1.141`. The old
  `10.1.1.141` in older docs is stale — confirm the current `host` from the API
  (`GET /proxy/protect/api/bridges` → `host` field).
- Controller = the **UCG-Fiber console** at `10.1.1.1` (UniFi OS 5.1.26, Protect 7.1.87).
  Root SSH to it via `~/.ssh/config` host `router` (key auth).
- The `isSshEnabled` toggle exists **only on the internal `/proxy/protect/api/bridges/<id>`
  path**, which requires a logged-in **session cookie + CSRF token**. A Protect
  **Integration API key** (`X-API-KEY`, `/proxy/protect/integration/v1/...`) is read-only
  for this purpose — it can enumerate bridges but its PATCH schema rejects `isSshEnabled`
  ("must NOT have additional properties"). Root-on-console alone also does NOT get a
  Protect session (internal `/api/` → 401 for API-key/Bearer/mTLS-direct-cert).
- **Working method:** drive the user's already-authenticated browser session. From the
  Protect/Network web UI (past the self-signed cert), `fetch('/proxy/protect/api/bridges',
  {credentials:'include'})` returns 200 + an `x-csrf-token` response header; then
  `PATCH /proxy/protect/api/bridges/<id>` and `PATCH /proxy/protect/api/nvr` with
  `{"isSshEnabled":true}` and header `x-csrf-token`. Both return 200. **SSH came up
  immediately — no device reboot required.**
- Bridge id: `6a612ad103c80a03e4027261`, MAC `9041B23483DC`, name "USL Gateway".
- SSH in: `ssh ubnt@10.1.10.141` (password = the `webpass`, baked into
  `tools/keyhook/capture_key.sh`).

## Notes

- The controller may **re-disable SSH on reprovisioning**. If SSH stops working after
  a firmware update or re-adoption, repeat the process.
- The local web UI at `https://<DEVICE_IP>/` uses its own credentials (username `ubnt`,
  password visible in the Protect controller under device settings).
- The CSRF token comes from the `x-updated-csrf-token` response header on login.
  It may also be refreshed on subsequent API responses — always use the latest one.
- The device's local API uses `/api/1.1/` (not `/api/1.0/`).
